'use strict';
// tests/fleetConformance.test.js
//
// Pins lib/engines/fleetConformance.js — "which firewall is configured unlike
// its peers?", the only analytic in the roadmap that DISCOVERS checks rather
// than evaluating the curated 45-check library.
//
// ⛔ THE THING THIS FILE MOSTLY EXISTS TO HOLD IS A REFUSAL, NOT A NUMBER.
// The arithmetic here is easy and it would be just as easy with the wrong
// wording around it. Live on the reference fleet, `global.admin-ssh-port` is 22
// on four FortiGates and 5022 on OKF(F2): the MINORITY is the only firewall not
// on the default SSH port, i.e. the hardened one, and the majority is the
// weaker configuration. An engine that named the minority as the problem would
// have told an operator to undo the only hardening in the cohort — a confident
// false finding, generated at fleet scale, on a product whose pitch is that it
// does not assert without evidence. So the vocabulary test below is not
// housekeeping; it is the feature.
//
// The second thing it holds is the cohort key. `(vendor, mgmt_method)`, never
// vendor: TUG is the only Palo Alto collected over SSH and its parser emits an
// entirely different structure, so grouped by vendor it would "differ" on
// essentially every path and every one of those findings would be false.
//
// Fixtures are the live fleet as measured 2026-09-25 — 5 FortiGates on SSH
// (21 value deviations), 10 Palo Altos on the API (3, after `netmask` and the
// other identity paths are excluded), and TUG alone in `paloalto/ssh`.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
  buildCohorts,
  enumeratePaths,
  findDeviations,
  summariseConformance,
  maxMinorityFor,
  identityReason,
  CONFORMANCE_CLAIM,
  MAX_DEPTH,
  MIN_COHORT,
  MINORITY_MAX_FRACTION,
  MAX_PATHS_PER_DEVICE,
  IDENTITY_LEAVES,
  STATUS,
  EXCLUSION,
  PRESENCE_KIND,
} = require('../lib/engines/fleetConformance');

// ── fixtures ────────────────────────────────────────────────────────────────

function dev(name, vendor, mgmt_method, config_parsed) {
  return { id: `id-${name}`, name, vendor, mgmt_method, config_parsed };
}

/**
 * n devices in one cohort, each config produced by fn(i). The name carries the
 * cohort so ids stay unique across cohorts — live they are UUIDs, and a fixture
 * that reused an id would have two firewalls sharing one row in the ranking.
 */
function cohortOf(n, vendor, method, fn) {
  return Array.from({ length: n }, (_, i) => dev(`${vendor}-${method}-fw${i}`, vendor, method, fn(i)));
}

function only(cohorts, key) {
  const c = cohorts.find((x) => x.key === key);
  assert.ok(c, `expected a cohort keyed ${key}, got ${cohorts.map((x) => x.key).join(', ')}`);
  return c;
}

function run(devices) {
  return buildCohorts(devices).map(findDeviations);
}

function pathsOf(list) {
  return list.map((d) => d.path).sort();
}

// ── 1. cohorts ──────────────────────────────────────────────────────────────

describe('cohorts are (vendor, mgmt_method)', () => {
  it('splits one vendor across two access methods into two cohorts', () => {
    const devices = [
      ...cohortOf(3, 'fortinet', 'ssh', () => ({ a: { b: 1 } })),
      ...cohortOf(3, 'fortinet', 'api', () => ({ a: { b: 1 } })),
    ];
    const cohorts = buildCohorts(devices);
    assert.deepEqual(cohorts.map((c) => c.key), ['fortinet/api', 'fortinet/ssh']);
    for (const c of cohorts) assert.equal(c.comparableCount, 3);
  });

  it('⛔ a mixed-method vendor does NOT form one cohort of six', () => {
    // The whole design. Merged, these six would be a measured cohort; kept
    // apart they are two cohorts of three, and neither can report anything.
    const devices = [
      ...cohortOf(3, 'fortinet', 'ssh', () => ({ a: { b: 1 } })),
      ...cohortOf(3, 'fortinet', 'api', () => ({ a: { b: 1 } })),
    ];
    for (const c of buildCohorts(devices)) assert.notEqual(c.comparableCount, 6);
  });

  it('⛔ the lone Palo Alto on SSH is its own cohort and yields nothing', () => {
    // Live: TUG. Its SSH parser emits tree/hostname/sw_version where the ten on
    // the API emit devices/shared/mgt-config, so grouped by vendor it would
    // differ on essentially every path — all of it false.
    const devices = [
      ...cohortOf(10, 'paloalto', 'api', () => ({ system_info: { model: 'PA-460' } })),
      dev('TUG', 'paloalto', 'ssh', { tree: { x: 1 }, hostname: 'tug' }),
    ];
    const results = run(devices);
    const tug = results.find((r) => r.cohortKey === 'paloalto/ssh');
    assert.equal(tug.status, STATUS.INSUFFICIENT_COHORT);
    assert.equal(tug.comparableCount, 1);
    assert.equal(tug.valueDeviations.length, 0);
    assert.equal(tug.presenceDeviations.length, 0);
  });

  it('a device with no vendor or no access method is excluded, with a reason', () => {
    const cohorts = buildCohorts([
      dev('a', 'fortinet', null, { x: { y: 1 } }),
      dev('b', null, 'ssh', { x: { y: 1 } }),
      dev('c', 'fortinet', 'ssh', { x: { y: 1 } }),
    ]);
    const keyless = cohorts.find((c) => c.key === null);
    assert.equal(keyless.excludedCount, 2);
    for (const e of keyless.excluded) {
      assert.equal(e.reason, EXCLUSION.NO_COHORT_KEY);
      assert.ok(e.detail.length > 40);
    }
  });
});

// ── 2. a cohort too small produces its own state, never an all-clear ────────

describe('⛔ a cohort under MIN_COHORT says so, rather than reporting nothing', () => {
  it('MIN_COHORT is 3', () => {
    assert.equal(MIN_COHORT, 3);
  });

  for (const n of [1, 2]) {
    it(`a cohort of ${n} is insufficient_cohort and carries the count`, () => {
      const [r] = run(cohortOf(n, 'fortinet', 'ssh', (i) => ({ a: { b: i } })));
      assert.equal(r.status, STATUS.INSUFFICIENT_COHORT);
      assert.equal(r.comparableCount, n);
      assert.match(r.limit, new RegExp(`\\b${n}\\b`));
      assert.match(r.limit, /\b3\b/);
      // ⛔ NOT an empty "no deviations". The list is empty AND the status says
      // nothing was compared; a caller reading only the list would otherwise
      // render a cohort nobody looked at as a clean one.
      assert.equal(r.valueDeviations.length, 0);
      assert.equal(r.presenceDeviations.length, 0);
      assert.equal(r.comparedPaths, 0);
    });
  }

  it('⛔ "nothing compared" and "compared, nothing reportable" are different states', () => {
    // Three devices CAN be compared and structurally cannot produce a minority
    // inside the threshold — the smallest split available to them is 1 of 3,
    // i.e. 33%. That is reported as its own state with what it compared, not
    // folded into either an empty result or insufficient_cohort.
    const [r] = run(cohortOf(3, 'fortinet', 'ssh', (i) => ({ a: { b: i === 0 ? 'x' : 'y' } })));
    assert.equal(r.status, STATUS.THRESHOLD_UNREACHABLE);
    assert.notEqual(r.status, STATUS.INSUFFICIENT_COHORT);
    assert.equal(r.comparableCount, 3);
    assert.equal(r.comparedPaths, 1);
    assert.equal(r.valueDeviations.length, 0);
    assert.ok(r.limit.length > 40);
  });
});

// ── 3. the minority threshold ──────────────────────────────────────────────

describe('⛔ the minority threshold is stated, and the boundary holds both ways', () => {
  it('is a quarter of the cohort, floored', () => {
    assert.equal(MINORITY_MAX_FRACTION, 0.25);
    assert.equal(maxMinorityFor(5), 1);
    assert.equal(maxMinorityFor(10), 2);
    assert.equal(maxMinorityFor(3), 0);
    assert.equal(maxMinorityFor(2), 0);
  });

  it('⛔ the ceiling is always below half, so a majority is always strict', () => {
    // The strict-majority rule and the threshold are separate checks, and this
    // pins the RELATION rather than the number: whatever the fraction becomes,
    // a "minority" may never be half the cohort or more.
    for (let n = MIN_COHORT; n <= 40; n += 1) {
      assert.ok(maxMinorityFor(n) < n / 2, `ceiling for ${n} must stay under half`);
    }
  });

  // n = 5: 4-vs-1 is an odd-one-out; 3-vs-2 is a fleet split down the middle.
  it('n=5: 4-vs-1 is reported', () => {
    const [r] = run(cohortOf(5, 'fortinet', 'ssh', (i) => ({ g: { p: i === 0 ? 'x' : 'y' } })));
    assert.equal(r.status, STATUS.MEASURED);
    assert.deepEqual(pathsOf(r.valueDeviations), ['g.p']);
    assert.equal(r.valueDeviations[0].minorityCount, 1);
    assert.equal(r.valueDeviations[0].majority.count, 4);
  });

  it('n=5: 3-vs-2 is NOT reported', () => {
    const [r] = run(cohortOf(5, 'fortinet', 'ssh', (i) => ({ g: { p: i < 2 ? 'x' : 'y' } })));
    assert.equal(r.status, STATUS.MEASURED);
    assert.equal(r.valueDeviations.length, 0);
    // ⛔ and it was genuinely compared — this is not a path that fell out of
    // enumeration, it is one the threshold declined to call an odd-one-out.
    assert.equal(r.comparedPaths, 1);
  });

  // n = 10: live, 9-vs-1 and 8-vs-2 are the real findings; 7-vs-3 is not.
  it('n=10: 9-vs-1 and 8-vs-2 are reported', () => {
    const [r] = run(cohortOf(10, 'paloalto', 'api', (i) => ({
      s: { nine_one: i === 0 ? 'a' : 'b', eight_two: i < 2 ? 'a' : 'b' },
    })));
    assert.deepEqual(pathsOf(r.valueDeviations), ['s.eight_two', 's.nine_one']);
  });

  it('n=10: 7-vs-3 is NOT reported', () => {
    const [r] = run(cohortOf(10, 'paloalto', 'api', (i) => ({ s: { p: i < 3 ? 'a' : 'b' } })));
    assert.equal(r.valueDeviations.length, 0);
    assert.equal(r.comparedPaths, 1);
  });

  it('a minority spread over several values still counts as one deviation', () => {
    // 8 agree, two disagree in different directions. The path is one question,
    // and both dissenting values travel with it rather than one being dropped.
    const [r] = run(cohortOf(10, 'paloalto', 'api', (i) => ({
      s: { p: i === 0 ? 'a' : i === 1 ? 'b' : 'c' },
    })));
    assert.equal(r.valueDeviations.length, 1);
    const d = r.valueDeviations[0];
    assert.equal(d.majority.count, 8);
    assert.equal(d.minorityCount, 2);
    assert.equal(d.minority.length, 2);
    assert.equal(d.distinctValues, 3);
  });

  it('a cohort with no majority value at all reports nothing', () => {
    const [r] = run(cohortOf(10, 'paloalto', 'api', (i) => ({ s: { p: i < 5 ? 'a' : 'b' } })));
    assert.equal(r.valueDeviations.length, 0);
  });
});

// ── 4. identity paths ──────────────────────────────────────────────────────

describe('⛔ identity-by-nature paths are excluded, or they manufacture noise', () => {
  it('netmask specifically produces no finding, however lopsided it is', () => {
    // Live proof: system_info.netmask fires 9-vs-1 on HRIS at depth 3, because
    // HRIS is on a /29 and the others are on /24s. Every firewall legitimately
    // has its own management address; there is no version of that finding an
    // operator can act on.
    const [r] = run(cohortOf(10, 'paloalto', 'api', (i) => ({
      system_info: {
        netmask: i === 0 ? '255.255.255.248' : '255.255.255.0',
        'device-dictionary-version': i === 0 ? '233-736' : '244-759',
      },
    })));
    assert.deepEqual(pathsOf(r.valueDeviations), ['system_info.device-dictionary-version']);
    for (const d of r.valueDeviations) assert.doesNotMatch(d.path, /netmask/);
    for (const d of r.valueDeviations) assert.doesNotMatch(d.statement, /netmask/);
    assert.ok(r.identityPathsSkipped >= 1);
    assert.match(identityReason('netmask'), /mask/i);
  });

  it('every excluded leaf carries a reason, and the list is named not inferred', () => {
    for (const [leaf, reason] of Object.entries(IDENTITY_LEAVES)) {
      assert.equal(typeof reason, 'string', `${leaf} needs a reason`);
      assert.ok(reason.length > 15, `${leaf}'s reason is too thin to review: ${reason}`);
    }
    for (const leaf of ['hostname', 'serial', 'uptime', 'mac-address', 'model', 'ip-address']) {
      assert.ok(identityReason(leaf), `${leaf} is identity by nature`);
    }
  });

  it('matching is on the whole last segment, never a substring', () => {
    // ⛔ THE TRAP. `dns.server-hostname` ENDS IN "hostname" and is the DNS
    // server's name, not the firewall's — it is a real presence deviation on
    // the live fleet. A substring or regex match would have swallowed it, along
    // with dns.primary, dns.secondary and log_syslogd.server: four of the
    // findings this analytic exists to produce.
    assert.equal(identityReason('server-hostname'), null);
    assert.equal(identityReason('admin-server-cert'), null);
    assert.equal(identityReason('primary'), null);
    assert.equal(identityReason('secondary'), null);
    assert.equal(identityReason('server'), null);
    assert.equal(identityReason('modelling-mode'), null);
  });

  it('normalises case, underscores and the @_ XML attribute prefix', () => {
    assert.ok(identityReason('MAC_Address'));
    assert.ok(identityReason('@_serial'));
    assert.ok(identityReason('Device_Name'));
  });

  it('a real DNS or syslog destination difference survives the exclusion', () => {
    const [r] = run(cohortOf(5, 'fortinet', 'ssh', (i) => ({
      dns: { primary: i === 0 ? '8.8.8.8' : '96.45.45.45' },
      log_syslogd: { server: i === 0 ? '192.168.6.111' : '4.145.105.175' },
    })));
    assert.deepEqual(pathsOf(r.valueDeviations), ['dns.primary', 'log_syslogd.server']);
  });
});

// ── 5. presence vs value ───────────────────────────────────────────────────

describe('⛔ presence-divergence and value-divergence are separate signals', () => {
  it('a value difference and a missing setting land in different lists', () => {
    const [r] = run(cohortOf(5, 'fortinet', 'ssh', (i) => {
      const g = { 'admin-ssh-port': i === 0 ? '5022' : '22' };
      if (i !== 0) g['admin-hsts-max-age'] = '0';
      return { global: g };
    }));
    assert.deepEqual(pathsOf(r.valueDeviations), ['global.admin-ssh-port']);
    assert.deepEqual(pathsOf(r.presenceDeviations), ['global.admin-hsts-max-age']);
    // ⛔ no path may appear in both — they answer different questions and the
    // presence one is the weaker claim.
    const v = new Set(pathsOf(r.valueDeviations));
    for (const p of pathsOf(r.presenceDeviations)) assert.equal(v.has(p), false);
  });

  it('a path some devices lack is never also assessed for value', () => {
    // Four devices have it and disagree 3-vs-1; the fifth does not have it at
    // all. Answering the value question over the subset would use a
    // denominator the reader would take for the cohort.
    const [r] = run(cohortOf(5, 'fortinet', 'ssh', (i) => (
      i === 4 ? { global: { other: 1 } } : { global: { other: 1, p: i === 0 ? 'x' : 'y' } }
    )));
    assert.equal(r.valueDeviations.length, 0);
    assert.deepEqual(pathsOf(r.presenceDeviations), ['global.p']);
  });

  it('presence obeys the same minority threshold', () => {
    // 3 have it, 2 do not: at n=5 the ceiling is 1, so this is not an
    // odd-one-out in either list.
    const [r] = run(cohortOf(5, 'fortinet', 'ssh', (i) => (
      i < 2 ? { global: { a: 1 } } : { global: { a: 1, b: 2 } }
    )));
    assert.equal(r.presenceDeviations.length, 0);
  });

  it('⛔ a whole missing SECTION is one item, not one per setting', () => {
    // Live: TSR_EKC has no `system_info` block at all, which naively reads as
    // six unrelated deviations when it is a single gap in what was collected.
    const [r] = run(cohortOf(5, 'fortinet', 'ssh', (i) => (
      i === 0
        ? { global: { a: 1 } }
        : { global: { a: 1 }, system_info: { build: 1, vdom_mode: 'x', version_string: 'v' } }
    )));
    assert.equal(r.presenceDeviations.length, 1);
    const p = r.presenceDeviations[0];
    assert.equal(p.kind, PRESENCE_KIND.SECTION);
    assert.equal(p.path, 'system_info');
    assert.equal(p.paths.length, 3);
    assert.equal(p.absentCount, 1);
    // and it says out loud that this may be about collection, not configuration
    assert.match(p.statement, /collected/i);
  });

  it('a setting missing from a section the device otherwise has stays individual', () => {
    const [r] = run(cohortOf(5, 'fortinet', 'ssh', (i) => (
      i === 0 ? { global: { a: 1 } } : { global: { a: 1, b: 2 } }
    )));
    assert.equal(r.presenceDeviations.length, 1);
    assert.equal(r.presenceDeviations[0].kind, PRESENCE_KIND.SETTING);
    assert.equal(r.presenceDeviations[0].path, 'global.b');
  });
});

// ── 6. ⛔ a device with no parsed config ────────────────────────────────────

describe('⛔ a device with no parsed config is EXCLUDED and COUNTED', () => {
  // This is the case that regresses silently. A firewall SecVault cannot read
  // contributes no deviation — so left uncounted it is the best-behaved member
  // of its cohort, which is this codebase's most-repeated bug wearing this
  // feature's clothes.

  const withGap = (missing) => [
    ...cohortOf(5, 'fortinet', 'ssh', (i) => ({ g: { p: i === 0 ? 'x' : 'y' } })),
    dev('DARK', 'fortinet', 'ssh', missing),
  ];

  for (const [label, missing, reason] of [
    ['null', null, EXCLUSION.NO_CONFIG],
    ['undefined', undefined, EXCLUSION.NO_CONFIG],
    ['an empty object', {}, EXCLUSION.UNUSABLE_CONFIG],
    ['an array', [1, 2, 3], EXCLUSION.UNUSABLE_CONFIG],
    ['a bare string', 'config text', EXCLUSION.UNUSABLE_CONFIG],
    ['a number', 7, EXCLUSION.UNUSABLE_CONFIG],
    ['an object of arrays only', { rules: [1, 2] }, EXCLUSION.UNUSABLE_CONFIG],
  ]) {
    it(`${label} is counted as excluded, with a reason`, () => {
      const [r] = run(withGap(missing));
      assert.equal(r.status, STATUS.MEASURED);
      assert.equal(r.excludedCount, 1);
      assert.equal(r.comparableCount, 5);
      assert.equal(r.deviceCount, 6);
      assert.equal(r.excluded[0].deviceName, 'DARK');
      assert.equal(r.excluded[0].reason, reason);
      assert.ok(r.excluded[0].detail.length > 40);
    });
  }

  it('⛔ it is NEVER treated as agreeing with everyone', () => {
    const [r] = run(withGap(null));
    const d = r.valueDeviations[0];
    // the cohort the finding is stated over is the FIVE that were compared
    assert.equal(d.cohortSize, 5);
    assert.equal(d.majority.count, 4);
    assert.match(d.statement, /4 of 5/);
    // and DARK is on neither side of it
    const named = [...d.majority.devices, ...d.minority.flatMap((g) => g.devices)];
    assert.equal(named.some((x) => x.deviceName === 'DARK'), false);
    // nor is it in the ranked fleet list, where a 0 means "compared and matches"
    const s = summariseConformance([r]);
    assert.equal(s.devices.some((x) => x.deviceName === 'DARK'), false);
    assert.equal(s.devicesExcluded, 1);
    assert.equal(s.devicesCompared, 5);
    assert.equal(s.excluded[0].deviceName, 'DARK');
  });

  it('a compared firewall with nothing to report IS in the list, at zero', () => {
    // The distinction the previous test rests on: absent means never assessed,
    // zero means assessed and matching. Collapsing them would make an
    // uncollectable firewall indistinguishable from a conforming one.
    const [r] = run(cohortOf(5, 'fortinet', 'ssh', (i) => ({ g: { p: i === 0 ? 'x' : 'y' } })));
    const s = summariseConformance([r]);
    assert.equal(s.devices.length, 5);
    assert.equal(s.devices.filter((x) => x.valueMinorityCount === 0).length, 4);
  });

  it('a cohort emptied by exclusions falls to insufficient_cohort, not to clean', () => {
    const [r] = run([
      dev('a', 'fortinet', 'ssh', null),
      dev('b', 'fortinet', 'ssh', null),
      dev('c', 'fortinet', 'ssh', {}),
    ]);
    assert.equal(r.status, STATUS.INSUFFICIENT_COHORT);
    assert.equal(r.comparableCount, 0);
    assert.equal(r.excludedCount, 3);
  });
});

// ── 7. path enumeration: arrays, depth, cardinality, junk ──────────────────

describe('⛔ arrays are not descended into', () => {
  it('a 721-rule device contributes no paths from its rules', () => {
    const rules = Array.from({ length: 721 }, (_, i) => ({ id: i, action: 'allow' }));
    const paths = enumeratePaths({ global: { a: 1 }, rules });
    assert.deepEqual([...paths.keys()], ['global.a']);
  });

  it('two devices whose rule arrays differ produce no deviation', () => {
    // Rule 7 on one firewall is not "the same setting" as rule 7 on another:
    // array members are keyed by position, and position is not a name.
    const [r] = run(cohortOf(5, 'fortinet', 'ssh', (i) => ({
      global: { a: 1 },
      rules: [{ name: `r${i}`, action: i === 0 ? 'deny' : 'allow' }],
    })));
    assert.equal(r.valueDeviations.length, 0);
    assert.equal(r.presenceDeviations.length, 0);
  });
});

describe('depth is bounded', () => {
  it(`MAX_DEPTH is ${MAX_DEPTH}, and nothing below it is enumerated`, () => {
    assert.equal(MAX_DEPTH, 3);
    const cfg = { a: { b: { c: 1, d: { e: 2 } } } };
    assert.deepEqual([...enumeratePaths(cfg).keys()], ['a.b.c']);
  });

  it('a container sitting at the depth limit is not compared as a value', () => {
    // Comparing whole subtrees as opaque blobs would report a deviation
    // whenever any leaf anywhere beneath differed, with no way to say which.
    const [r] = run(cohortOf(5, 'fortinet', 'ssh', (i) => ({
      a: { b: { c: { deep: i === 0 ? 'x' : 'y' } } },
    })));
    assert.equal(r.valueDeviations.length, 0);
    assert.equal(r.comparedPaths, 0);
  });

  it('a deeper depth can be asked for explicitly', () => {
    const cfg = { a: { b: { c: { d: 1 } } } };
    assert.equal(enumeratePaths(cfg, 4).size, 1);
    assert.equal(enumeratePaths(cfg, 3).size, 0);
    assert.equal(enumeratePaths(cfg, 0).size, 0);
  });
});

describe('cardinality is bounded, and an over-budget device is excluded whole', () => {
  it('a config yielding more than MAX_PATHS_PER_DEVICE is excluded, not truncated', () => {
    // ⛔ Truncation would leave a device APPEARING to lack the paths that were
    // cut, manufacturing presence deviations out of our own bound.
    const fat = { top: {} };
    for (let i = 0; i < MAX_PATHS_PER_DEVICE + 10; i += 1) fat.top[`k${i}`] = i;
    const [r] = run([
      ...cohortOf(5, 'fortinet', 'ssh', () => ({ g: { p: 1 } })),
      dev('FAT', 'fortinet', 'ssh', fat),
    ]);
    assert.equal(r.excludedCount, 1);
    assert.equal(r.excluded[0].reason, EXCLUSION.TOO_MANY_PATHS);
    assert.equal(r.comparableCount, 5);
  });

  it('enumeration stops at the bound rather than running on', () => {
    const fat = { top: {} };
    for (let i = 0; i < MAX_PATHS_PER_DEVICE * 2; i += 1) fat.top[`k${i}`] = i;
    assert.equal(enumeratePaths(fat).size, MAX_PATHS_PER_DEVICE);
  });
});

describe('malformed input does not throw', () => {
  it('enumeratePaths survives anything', () => {
    for (const junk of [null, undefined, '', 'text', 0, 7, true, [], [1, 2], NaN]) {
      assert.equal(enumeratePaths(junk).size, 0);
    }
    assert.equal(enumeratePaths({ a: { b: 1 } }, 'not a number').size, 0);
    assert.equal(enumeratePaths({ a: { b: 1 } }, -5).size, 0);
  });

  it('a cyclic structure is bounded by depth rather than looping', () => {
    const a = { name: 'a' };
    a.self = a;
    assert.doesNotThrow(() => enumeratePaths(a));
    assert.ok(enumeratePaths(a).has('name'));
  });

  it('a null-prototype object and odd keys are handled', () => {
    const o = Object.create(null);
    o.section = { constructor: 'x', toString: 'y', 'has.a.dot': 'z' };
    const paths = enumeratePaths(o);
    assert.equal(paths.size, 3);
    assert.equal(paths.get('section.constructor').value, 'x');
  });

  it('a null VALUE is a value, not an absence', () => {
    // The firewall reported the key and reported nothing in it. That is a
    // different fact from the key not being there, and this engine's whole
    // subject is not collapsing those two.
    const [r] = run(cohortOf(5, 'fortinet', 'ssh', (i) => ({ g: { p: i === 0 ? null : 'y' } })));
    assert.equal(r.valueDeviations.length, 1);
    assert.equal(r.presenceDeviations.length, 0);
    assert.equal(r.valueDeviations[0].minority[0].value, null);
    assert.match(r.valueDeviations[0].statement, /null/);
  });

  it('buildCohorts, findDeviations and summariseConformance survive junk', () => {
    for (const junk of [null, undefined, 'x', 7, {}]) {
      assert.doesNotThrow(() => buildCohorts(junk));
      assert.doesNotThrow(() => findDeviations(junk));
      assert.doesNotThrow(() => summariseConformance(junk));
    }
    assert.deepEqual(buildCohorts(null), []);
    assert.equal(findDeviations(undefined).status, STATUS.INSUFFICIENT_COHORT);
    assert.equal(summariseConformance(null).cohorts, 0);
    assert.doesNotThrow(() => buildCohorts([null, undefined, {}]));
  });
});

// ── 8. the fleet summary ───────────────────────────────────────────────────

describe('the fleet summary answers "which firewall is unlike its peers"', () => {
  const FLEET = [
    // 5 FortiGates on SSH, one of them built to a different standard
    ...cohortOf(5, 'fortinet', 'ssh', (i) => ({
      dns: { protocol: i === 0 ? 'cleartext' : 'dot' },
      global: { 'admin-ssh-port': i === 0 ? '5022' : '22', admintimeout: i === 0 ? '25' : '5' },
    })).map((d, i) => ({ ...d, name: i === 0 ? 'OKF(F2)' : d.name })),
    // 10 Palo Altos on the API, one lagging on content
    ...cohortOf(10, 'paloalto', 'api', (i) => ({
      system_info: {
        netmask: i === 0 ? '255.255.255.248' : '255.255.255.0',
        'device-dictionary-version': i === 1 ? '233-736' : '244-759',
      },
    })).map((d, i) => ({ ...d, name: i === 1 ? 'PAKFood' : d.name })),
    // and TUG alone
    dev('TUG', 'paloalto', 'ssh', { tree: { a: 1 } }),
  ];

  it('ranks the firewall that differs most often first', () => {
    const s = summariseConformance(run(FLEET));
    assert.equal(s.devices[0].deviceName, 'OKF(F2)');
    assert.equal(s.devices[0].valueMinorityCount, 3);
    assert.equal(s.devices.find((d) => d.deviceName === 'PAKFood').valueMinorityCount, 1);
  });

  it('counts the cohorts that could not be measured, by name', () => {
    const s = summariseConformance(run(FLEET));
    assert.equal(s.cohorts, 3);
    assert.equal(s.measuredCohorts, 2);
    assert.deepEqual(s.insufficientCohorts.map((c) => c.cohortKey), ['paloalto/ssh']);
    assert.equal(s.insufficientCohorts[0].comparableCount, 1);
    // TUG was never compared, so it is not in the ranking at all
    assert.equal(s.devices.some((d) => d.deviceName === 'TUG'), false);
    // ⛔ and TUG is not counted as compared either — it is comparable and was
    // never compared against anything, which is a different fact.
    assert.equal(s.devicesCompared, 15);
    assert.equal(s.devicesInUnreportableCohorts, 1);
  });

  it('carries the identity skips and the claim to the top level', () => {
    const s = summariseConformance(run(FLEET));
    assert.ok(s.identityPathsSkipped >= 1);
    assert.equal(s.claim, CONFORMANCE_CLAIM);
    assert.equal(s.maxDepth, MAX_DEPTH);
    assert.equal(s.minorityMaxFraction, MINORITY_MAX_FRACTION);
  });

  it('⛔ reports no score, no percentage and no band', () => {
    // A count of differences is not a measure of quality in either direction.
    // Given a score's shape it would be read as one, and the firewall at the
    // top of this list is as likely to be the best-configured as the worst.
    const s = summariseConformance(run(FLEET));
    const json = JSON.stringify(s);
    assert.doesNotMatch(json, /"score/i);
    assert.doesNotMatch(json, /"(grade|band|rating|health)"/i);
    assert.doesNotMatch(json, /%/);
  });

  it('survives a JSON round trip, as a route would send it', () => {
    const s = JSON.parse(JSON.stringify(summariseConformance(run(FLEET))));
    assert.equal(s.claim, CONFORMANCE_CLAIM);
    assert.equal(s.devices[0].deviceName, 'OKF(F2)');
  });
});

// ── 9. ⛔ THE REFUSAL — majority is not correctness ─────────────────────────

const FORBIDDEN = [
  /\bmisconfig\w*/i,
  /\bwrong\b/i,
  /\bincorrect\w*/i,
  /\bnon-?compliant\b/i,
  /\bcompliant\b/i,
  /\bviolat\w*/i,
  /\bshould\b/i,
  /\bmust\b/i,
  /\bfix(es|ed|ing)?\b/i,
  /\bremediat\w*/i,
  /\bfault\w*/i,
  /\bbad\b/i,
  /\binvalid\b/i,
  /\bbreach\w*/i,
];

/** Every string anywhere in a structure, however deep. */
function everyString(value, out = []) {
  if (typeof value === 'string') out.push(value);
  else if (Array.isArray(value)) value.forEach((v) => everyString(v, out));
  else if (value && typeof value === 'object') Object.values(value).forEach((v) => everyString(v, out));
  return out;
}

const SRC_PATH = path.join(__dirname, '..', 'lib', 'engines', 'fleetConformance.js');
const RAW_SRC = fs.readFileSync(SRC_PATH, 'utf8');

/** ⛔ COMMENTS FIRST. See the test below for why this is not a formality. */
function stripComments(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/^[ \t]*\/\/[^\n]*$/gm, '');
}

const STRIPPED_SRC = stripComments(RAW_SRC);

describe('⛔ MAJORITY IS NOT CORRECTNESS — the vocabulary of judgement is absent', () => {
  it('the claim states what a deviation does and does not mean', () => {
    assert.match(CONFORMANCE_CLAIM, /differs/i);
    assert.match(CONFORMANCE_CLAIM, /does not know/i);
    assert.match(CONFORMANCE_CLAIM, /deliberately/i);
    for (const bad of FORBIDDEN) {
      assert.doesNotMatch(CONFORMANCE_CLAIM, bad, `the claim itself must avoid ${bad}`);
    }
  });

  it('the claim travels on every answer, not only on the summary', () => {
    const results = run([
      ...cohortOf(5, 'fortinet', 'ssh', (i) => ({ g: { p: i === 0 ? 'x' : 'y', q: i === 0 ? undefined : 1 } })),
      dev('DARK', 'fortinet', 'ssh', null),
    ]);
    for (const r of results) {
      assert.equal(r.claim, CONFORMANCE_CLAIM);
      for (const d of [...r.valueDeviations, ...r.presenceDeviations]) {
        assert.equal(d.claim, CONFORMANCE_CLAIM);
      }
    }
  });

  it('no string the engine can emit carries the vocabulary of judgement', () => {
    // Exercised over every state this engine has: measured, insufficient,
    // threshold-unreachable, excluded devices, value and presence deviations,
    // section collapse, and the fleet summary.
    const results = run([
      ...cohortOf(5, 'fortinet', 'ssh', (i) => (
        i === 0
          ? { dns: { protocol: 'cleartext' }, global: { 'admin-ssh-port': '5022' } }
          : {
            dns: { protocol: 'dot' },
            global: { 'admin-ssh-port': '22', 'admin-hsts-max-age': '0' },
            system_info: { build: 1, model: 'FG-60F' },
          }
      )),
      dev('DARK', 'fortinet', 'ssh', null),
      dev('ODD', 'fortinet', 'ssh', 'raw text'),
      ...cohortOf(3, 'paloalto', 'api', (i) => ({ s: { p: i === 0 ? 'a' : 'b' } })),
      dev('TUG', 'paloalto', 'ssh', { tree: { a: 1 } }),
      dev('NOKEY', null, null, { a: { b: 1 } }),
      ...cohortOf(10, 'checkpoint', 'api', (i) => ({ s: { p: i < 2 ? 'a' : 'b', n: null } })),
    ]);
    const strings = everyString([results, summariseConformance(results)]);
    assert.ok(strings.length > 60, `expected the states to produce prose, got ${strings.length}`);
    for (const s of strings) {
      for (const bad of FORBIDDEN) {
        assert.doesNotMatch(s, bad, `emitted string carries ${bad}: ${s}`);
      }
    }
  });

  it('⛔ and no string LITERAL in the source carries it either — comments stripped FIRST', () => {
    // This repo has repeatedly had a source scan satisfied by the comment
    // explaining the thing it hunts. The next test proves the stripper works
    // by pointing it at words the header deliberately contains.
    for (const bad of FORBIDDEN) {
      const hit = STRIPPED_SRC.match(new RegExp(bad.source, 'gi'));
      assert.equal(hit, null, `source (comments stripped) carries ${bad}: ${hit}`);
    }
  });

  it('⛔ the stripper is proven, not assumed', () => {
    // The header explains the rule by naming the reading it refuses, in as many
    // words. If stripComments ever stopped working, the test above would go red
    // on the comment rather than green on nothing — and this test is what makes
    // that impossible to mistake for the scan being pointless.
    assert.match(RAW_SRC, /misconfigured/i);
    assert.match(RAW_SRC, /\bwrong\b/i);
    assert.doesNotMatch(STRIPPED_SRC, /misconfigured/i);
    assert.doesNotMatch(STRIPPED_SRC, /\bwrong\b/i);
    assert.ok(STRIPPED_SRC.length < RAW_SRC.length * 0.75, 'the comments are the majority of this file');
  });

  it('a deviation names both sides by what they report, and neither as the answer', () => {
    // The live case: OKF(F2) is the minority on admin-ssh-port and it is the
    // only firewall NOT on the default port.
    const [r] = run(cohortOf(5, 'fortinet', 'ssh', (i) => ({
      global: { 'admin-ssh-port': i === 0 ? '5022' : '22' },
    })).map((d, i) => ({ ...d, name: i === 0 ? 'OKF(F2)' : d.name })));
    const d = r.valueDeviations[0];
    assert.match(d.statement, /4 of 5/);
    assert.match(d.statement, /"22"/);
    assert.match(d.statement, /OKF\(F2\)/);
    assert.match(d.statement, /"5022"/);
    assert.equal(d.summary, '1 of 5 differ');
  });
});

// ── 10. purity ─────────────────────────────────────────────────────────────

describe('the engine is pure', () => {
  it('takes no pool, runs no query and reads no clock', () => {
    for (const bad of [/\bpool\b/i, /\bSELECT\b/, /\bquery\(/, /Date\.now/, /new Date/, /require\(/]) {
      assert.doesNotMatch(STRIPPED_SRC, bad, `a pure engine must not reference ${bad}`);
    }
  });

  it('does not mutate the devices it is given', () => {
    const devices = cohortOf(5, 'fortinet', 'ssh', (i) => ({ g: { p: i === 0 ? 'x' : 'y' } }));
    const before = JSON.stringify(devices);
    summariseConformance(buildCohorts(devices).map(findDeviations));
    assert.equal(JSON.stringify(devices), before);
  });

  it('is deterministic: the same fleet twice gives byte-identical answers', () => {
    const devices = [
      ...cohortOf(5, 'fortinet', 'ssh', (i) => ({ g: { p: i === 0 ? 'x' : 'y' } })),
      ...cohortOf(10, 'paloalto', 'api', (i) => ({ s: { q: i < 2 ? 'a' : 'b' } })),
    ];
    const a = JSON.stringify(summariseConformance(run(devices)));
    const b = JSON.stringify(summariseConformance(run(devices.slice().reverse())));
    assert.equal(a, b);
  });
});
