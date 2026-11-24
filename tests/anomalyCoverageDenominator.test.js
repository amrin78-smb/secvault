// tests/anomalyCoverageDenominator.test.js
//
// ⛔ WHY THIS EXISTS — A FIREWALL THAT WAS NEITHER JUDGED NOR COUNTED AS A GAP.
//
// v2.237.1 stopped `/alerts` asserting an all-clear when NOTHING had been
// judged, and recorded, in `AnomalyPanel.js`'s own comment, the residual it did
// not close: "a monitoring-only firewall and PAKFood (which sends no syslog)
// are invisible to it, so 13-of-16 judged reads exactly like 16." Writing a gap
// down does not close it.
//
// Both detectors took their DEVICE LIST from the evidence rather than from the
// fleet:
//   * `loadReportingGrid`'s dev CTE carried
//     `AND EXISTS (SELECT 1 FROM syslog_rollup_hourly r WHERE r.device_id = d.id)`,
//     so a firewall that has never produced a rollup row was not in the grid at
//     all — and `gatherAnomalies` iterates that grid.
//   * `loadDeniedSeries` derives its devices from a `reporting` CTE bounded to
//     the window, so a firewall dark for the whole window produced no series,
//     and the denied loop iterated the SERIES.
// Either way the device incremented no `states` bucket: absent from the
// numerator AND the denominator, which is the one arithmetic that cannot be
// noticed by looking at the number.
//
// ⛔ MEASURED ON PRODUCTION 2026-11-24: 17 active firewalls, `measured` 15,
// `no_data` **0**. The two uncounted were PAKFood (has never sent syslog) and
// StarUnion (added logs-only that afternoon, through the v2.237.0 feature).
// CLAUDE.md asserted PAKFood was "correctly `no_data`" while AnomalyPanel.js
// said it was invisible — two files disagreeing about one firewall, and the
// measured one was right.
//
// ⛔ THE FIX MUST ADD A COUNT AND NEVER A FINDING, and that is the assertion
// that matters most here. A firewall that never started is UNCOLLECTED, not
// silent; raising "stopped sending syslog" about it would send somebody hunting
// an outage that never happened — and would also put the fleet's quietest
// devices into the alert dispatcher. Every test below checks the findings list
// as well as the state tally.

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO = path.join(__dirname, '..');
const anomalyData = require('../lib/engines/anomalyDetectionsData');

const NOW = new Date(Date.UTC(2026, 10, 24, 8, 0, 0));
const DEV_SEEN = '11111111-1111-4111-8111-111111111111';
const DEV_NEVER = '22222222-2222-4222-8222-222222222222';

// ⛔ SQL COMMENTS ARE STRIPPED BEFORE ANY STATEMENT ASSERTION. The fix's own
// comment inside the query NAMES the predicate it removed, so a raw scan would
// read the explanation as the thing it forbids — the `notificationChannels.js`
// prose trap, which this repo has now hit three times.
const stripSqlComments = (sql) => sql
  .replace(/\/\*[\s\S]*?\*\//g, ' ')
  .replace(/--[^\n]*/g, ' ');

const stripJsComments = (src) => src
  .replace(/\/\*[\s\S]*?\*\//g, ' ')
  .replace(/(^|[^:])\/\/[^\n]*/g, '$1 ');

/**
 * A pool whose GRID contains two devices — one that reported throughout, one
 * that never reported a single hour — while the denied-series read returns
 * nothing at all for the second. That is the production shape.
 */
function stubPool({ deniedRows = null } = {}) {
  const seen = [];
  const hours = 24 * 28;
  return {
    seen,
    query: async (sql) => {
      seen.push(sql);
      if (/max\(bucket_hour\) AS last_at/.test(sql)) {
        // ⛔ Only the device that HAS reported appears here. The other is
        // absent, which is what makes `lastReportedAt` an explicit null rather
        // than a Date — the "never reported" arm, not "stopped long ago".
        return { rows: [{ device_id: DEV_SEEN, last_at: new Date(Date.UTC(2026, 10, 24, 7)) }] };
      }
      if (/generate_series/.test(sql)) {
        const rows = [];
        for (let i = 0; i < hours; i += 1) {
          const at = new Date(Date.UTC(2026, 9, 27, i));
          rows.push({ device_id: DEV_SEEN, device_name: 'REPORTING-FW', at, reported: true });
          rows.push({ device_id: DEV_NEVER, device_name: 'PAKFood', at, reported: false });
        }
        return { rows };
      }
      if (/FROM reporting/.test(sql) || /DENIED|deny/i.test(sql)) {
        if (deniedRows) return { rows: deniedRows };
        // ⛔ ONLY the reporting device has a series — which is the whole point.
        // A fixture that starved BOTH devices would make the no_data count 2
        // and the test would pass for the wrong reason, proving nothing about
        // whether the loop iterates the fleet or the series. (It did exactly
        // that on the first run.)
        const rows = [];
        for (let i = 0; i < hours; i += 1) {
          rows.push({
            device_id: DEV_SEEN,
            device_name: 'REPORTING-FW',
            at: new Date(Date.UTC(2026, 9, 27, i)),
            value: 10,
          });
        }
        return { rows };
      }
      return { rows: [] };
    },
  };
}

describe('⛔ a never-reporting firewall is COUNTED by both detectors', () => {
  it('device_silent counts it as no_data and raises nothing', async () => {
    const { findings, states } = await anomalyData.gatherAnomalies(stubPool(), { now: NOW });
    assert.equal(states.device_silent.no_data, 1,
      'a firewall that has never produced a rollup row must land in no_data, '
      + 'not vanish from the tally');
    assert.equal(
      findings.filter((f) => f.detector === 'device_silent' && f.deviceId === DEV_NEVER).length,
      0,
      'a firewall that never started is UNCOLLECTED, not silent — counting it '
      + 'must never raise "stopped sending syslog"');
  });

  it('⛔ denied_spike counts it too — the second detector was the same hole', async () => {
    // This is the half that a fix to the grid alone would have left open, and
    // CLAUDE.md names that trap by name: "a fix applied to one of two
    // detectors is a defect waiting to be rediscovered" (v2.228.10, where
    // detectSpike carried detectSilence's window-edge bug and nobody noticed).
    const { findings, states } = await anomalyData.gatherAnomalies(stubPool(), { now: NOW });
    assert.equal(states.denied_spike.no_data, 1,
      'the denied loop must iterate the FLEET, not the series it happened to '
      + 'read — a firewall with no series is a coverage gap, not an absence');
    assert.equal(
      findings.filter((f) => f.detector === 'denied_spike' && f.deviceId === DEV_NEVER).length,
      0);
  });

  it('the denominator is every active firewall, for both detectors', async () => {
    const { states } = await anomalyData.gatherAnomalies(stubPool(), { now: NOW });
    for (const d of ['device_silent', 'denied_spike']) {
      const s = states[d];
      const total = (s.measured || 0) + (s.no_data || 0)
        + (s.insufficient_baseline || 0) + (s.stopped_before_window || 0);
      assert.equal(total, 2,
        `${d} tallied ${total} of 2 firewalls — a device missing from every `
        + 'bucket is absent from the numerator AND the denominator, which is '
        + 'the one arithmetic error that cannot be seen in the result');
    }
  });

  it('⛔ the reporting firewall is still judged normally', async () => {
    // The guard above must not be bought by degrading everything to no_data.
    const { states } = await anomalyData.gatherAnomalies(stubPool(), { now: NOW });
    assert.equal(states.device_silent.measured, 1);
    assert.ok(states.device_silent.measured + states.device_silent.no_data === 2);
  });
});

describe('⛔ the grid SELECTS every active device, not only ones with evidence', () => {
  it('the generated statement does not gate devices on having a rollup row', async () => {
    let sql = '';
    await anomalyData.loadReportingGrid({
      query: async (q) => { sql = q; return { rows: [] }; },
    });
    const bare = stripSqlComments(sql);
    assert.match(bare, /FROM devices d/, 'the device list must come from devices');
    assert.match(bare, /d\.active\s*=\s*true/, 'only ACTIVE firewalls are in scope');
    // ⛔ The predicate that WAS the bug. Asserted negatively against the
    // comment-stripped text, because the comment explaining the removal quotes
    // it verbatim.
    assert.doesNotMatch(
      bare,
      /EXISTS\s*\(\s*SELECT[\s\S]{0,120}?syslog_rollup_hourly[\s\S]{0,80}?r\.device_id\s*=\s*d\.id/i,
      'gating the device list on an existing rollup row hides a firewall that '
      + 'has never reported from the detector AND from its own coverage count'
    );
  });

  it('⛔ the assertion above is not satisfied by the comment alone', async () => {
    // A guard this repo has watched pass on prose three times. The raw SQL
    // SHOULD still mention the predicate (the comment explains it); only the
    // stripped form may not.
    let sql = '';
    await anomalyData.loadReportingGrid({
      query: async (q) => { sql = q; return { rows: [] }; },
    });
    assert.notEqual(stripSqlComments(sql).length, sql.length,
      'the statement carries no SQL comment, so the strip step is untested — '
      + 'if the explanation was moved out, delete this assertion deliberately');
  });
});

describe('⛔ the collect loop does not poll a logs-only firewall', () => {
  // ⛔ A SOURCE ASSERTION, AND THE LIMIT IS STATED RATHER THAN HIDDEN.
  // `services/engine-worker.js` registers cron jobs at module load, so
  // `tests/moduleLoad.test.js` carries it parse-only and this suite cannot run
  // the loop. What a scan CAN prove is that the guard sits BEFORE the call it
  // guards — which is the regression that actually happened: v2.237.0 added
  // this `continue` to `vpn-session-poll` and `snmp-poll` and missed the third
  // loop, the only one that writes reachability.
  const src = stripJsComments(fs.readFileSync(path.join(REPO, 'services/engine-worker.js'), 'utf8'));

  it('runRuleVersionPullJob skips before it collects', () => {
    const start = src.indexOf('async function runRuleVersionPullJob');
    assert.ok(start > -1, 'runRuleVersionPullJob not found');
    const body = src.slice(start, start + 4000);
    const guard = body.indexOf('isMonitoringOnly(device)');
    const collect = body.indexOf('collectForDevice(device)');
    assert.ok(guard > -1,
      'the rule-version-pull loop has no monitoring-only guard, so a logs-only '
      + 'firewall gets a FAILED connectivity row for a poll nobody attempted');
    assert.ok(collect > -1, 'collectForDevice call not found');
    assert.ok(guard < collect,
      'the guard must run BEFORE collectForDevice — after it, the connectivity '
      + 'row has already been written and the device reads as "Failing"');
  });

  it('⛔ all three poll loops carry it, because two of three was the bug', () => {
    // The defect was not a missing idea, it was a missing APPLICATION of one.
    for (const fn of ['runRuleVersionPullJob', 'runVpnPollJob', 'runSnmpPollJob']) {
      const start = src.indexOf(`async function ${fn}`);
      if (start === -1) continue; // named differently; the next assertion covers the count
      const body = src.slice(start, start + 4000);
      assert.match(body, /isMonitoringOnly\(device\)/,
        `${fn} iterates devices without a monitoring-only guard`);
    }
    const guards = (src.match(/if \(isMonitoringOnly\(device\)\) continue;/g) || []).length;
    assert.ok(guards >= 3,
      `only ${guards} poll loop(s) skip a logs-only firewall; v2.237.0 shipped `
      + 'two of three and the missing one was the one that writes reachability');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// ⛔ A FIREWALL CANNOT HAVE BEEN SILENT BEFORE SECVAULT KNEW IT EXISTED.
//
// `syslog_rollup_hourly.device_id` is stamped at INGEST, so a rollup row cannot
// predate the device row. A newly-added firewall therefore has a grid that is
// silent by construction for everything before its creation, and detectSilence
// read that as one long silence run.
//
// Measured on production 2026-11-24, 48 minutes after the fleet's first
// logs-only device was added: "StarUnion stopped sending syslog — AT LEAST 671
// hours", about a firewall created at 14:28 that was sending at that moment.
// `device_silent` is a dispatched alert type, so on an installation with
// channels configured, ONBOARDING a firewall would email an outage alert.
// ─────────────────────────────────────────────────────────────────────────────
describe('⛔ onboarding a firewall does not raise a silence alert', () => {
  const { detectSilence } = require('../lib/engines/anomalyDetections');

  const grid = (flags) => flags.map((reported, i) => ({
    at: new Date(Date.UTC(2026, 10, 1, i)), reported,
  }));

  it('⛔ a run at index 0 of a BIRTH-TRIMMED grid has a KNOWN start', () => {
    // Index 0 is the creation hour: a fixed, recorded timestamp.
    const r = detectSilence(grid([false, false, false, true, true]), {
      minHours: 2, lastReportedAt: new Date(Date.UTC(2026, 10, 1, 4)),
      gridStartIsKnown: true,
    });
    assert.equal(r.state, 'measured');
    assert.equal(r.runs.length, 1);
    assert.equal(r.runs[0].truncated, false,
      'a grid trimmed to the device\'s creation has a FIXED index 0, so the '
      + 'start is the best-recorded fact about the run, not an unknown');
  });

  it('⛔ the window-edge case is UNCHANGED and still truncated', () => {
    // The default must stay safe: a caller that says nothing gets `truncated`.
    const r = detectSilence(grid([false, false, false, true, true]), {
      minHours: 2, lastReportedAt: new Date(Date.UTC(2026, 10, 1, 4)),
    });
    assert.equal(r.runs[0].truncated, true,
      'without the flag, index 0 is the window\'s MOVING left edge and the '
      + 'start is genuinely unknown — v2.228.10');
  });

  it('a device added this hour and reporting raises nothing', async () => {
    // The production shape: grid is just the hours since creation, all reported.
    const r = detectSilence(grid([true, true]), {
      minHours: 2, lastReportedAt: new Date(Date.UTC(2026, 10, 1, 1)),
      gridStartIsKnown: true,
    });
    assert.equal(r.runs.length, 0, 'a firewall added an hour ago and sending '
      + 'must not be reported as having stopped');
  });

  it('⛔ the grid query trims to the creation hour and says when it did', async () => {
    let sql = '';
    await anomalyData.loadReportingGrid({
      query: async (q) => { sql = q; return { rows: [] }; },
    });
    const bare = stripSqlComments(sql);
    assert.match(bare, /hours\.h\s*>=\s*dev\.born/,
      'each device\'s grid must start at its own creation hour');
    assert.match(bare, /LEAST\(\s*d\.created_at\s*,\s*now\(\)\s*\)/,
      'a created_at in the future is a clock disagreement and must not yield '
      + 'an EMPTY grid, which the all-silent branch reads as total silence');
    assert.match(bare, /grid_starts_at_birth/,
      'the caller cannot tell a fixed index 0 from a moving one without this');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// ⛔ THE WIRING, WHICH IS THE PART THAT GOES UNTESTED — AND DID.
//
// The tests above drive `detectSilence` directly and read the generated SQL.
// Mutation testing proved that left the MIDDLE unguarded: hardcoding
// `gridStartIsKnown: false` at the call site, and hardcoding
// `gridStartsAtBirth: true` when reading the column, both left the suite GREEN.
// Each would restore the false onboarding alert (or suppress a real
// window-edge truncation) with every assertion still passing. Same shape as
// `corpusAdvanceErrors` being composed inline and never consulted.
// ─────────────────────────────────────────────────────────────────────────────
describe('⛔ gatherAnomalies carries the birth flag from the grid to the detector', () => {
  const DEV = '33333333-3333-4333-8333-333333333333';
  const HOURS = 24 * 28;

  // A device silent from index 0 and reporting at the end: the shape a freshly
  // added firewall produces. `lastReportedAt` is a Date, so this is NOT the
  // never-reported arm — it is a measured run whose `truncated` flag is the
  // whole question.
  function poolWith(gridStartsAtBirth) {
    return {
      query: async (sql) => {
        if (/max\(bucket_hour\) AS last_at/.test(sql)) {
          return { rows: [{ device_id: DEV, last_at: new Date(Date.UTC(2026, 10, 24, 7)) }] };
        }
        if (/generate_series/.test(sql)) {
          return {
            rows: Array.from({ length: HOURS }, (_, i) => ({
              device_id: DEV,
              device_name: 'JUST-ADDED-FW',
              at: new Date(Date.UTC(2026, 9, 27, i)),
              reported: i >= HOURS - 2,
              grid_starts_at_birth: gridStartsAtBirth,
            })),
          };
        }
        return { rows: [] };
      },
    };
  }

  it('⛔ a birth-trimmed grid yields a finding that is NOT truncated', async () => {
    const { findings } = await anomalyData.gatherAnomalies(poolWith(true), { now: NOW });
    const f = findings.find((x) => x.detector === 'device_silent');
    assert.ok(f, 'expected a device_silent finding to assert against');
    assert.equal(f.truncated, false,
      'the call site dropped the flag: a run starting at the device\'s own '
      + 'creation hour would be reported as having an unknown start');
    assert.equal(f.hoursAreLowerBound, false);
    assert.doesNotMatch(f.naturalKey, /start-before-window$/,
      'a known start must not key on the moving-edge sentinel');
  });

  it('⛔ a window-edge grid still yields a TRUNCATED finding', async () => {
    const { findings } = await anomalyData.gatherAnomalies(poolWith(false), { now: NOW });
    const f = findings.find((x) => x.detector === 'device_silent');
    assert.ok(f);
    assert.equal(f.truncated, true,
      'the flag was hardcoded true: a genuine window-edge run would claim a '
      + 'start nobody measured, which is the v2.228.10 defect');
    assert.equal(f.hoursAreLowerBound, true);
    assert.match(f.naturalKey, /start-before-window$/);
  });

  it('⛔ an ABSENT column is read as false, never as truthy', async () => {
    // A projection that forgets the column must degrade to the SAFE answer.
    const pool = {
      query: async (sql) => {
        if (/max\(bucket_hour\) AS last_at/.test(sql)) {
          return { rows: [{ device_id: DEV, last_at: new Date(Date.UTC(2026, 10, 24, 7)) }] };
        }
        if (/generate_series/.test(sql)) {
          return {
            rows: Array.from({ length: HOURS }, (_, i) => ({
              device_id: DEV, device_name: 'NO-COLUMN-FW',
              at: new Date(Date.UTC(2026, 9, 27, i)), reported: i >= HOURS - 2,
            })),
          };
        }
        return { rows: [] };
      },
    };
    const { findings } = await anomalyData.gatherAnomalies(pool, { now: NOW });
    const f = findings.find((x) => x.detector === 'device_silent');
    assert.ok(f);
    assert.equal(f.truncated, true,
      'undefined must mean "we do not know the start", not "the start is known"');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// ⛔ EACH DETECTOR IS SCORED OVER THE SPAN ITS FINDINGS COVER.
//
// `rateDrift` was handed `days` (28) for BOTH detectors. `device_silent` walks
// the whole grid so that is right; `detectSpike` judges only the last
// `DEFAULT_JUDGE_WINDOW_HOURS` (24) and trains on the rest, so its findings
// span ONE DAY and dividing them by 28 understates the rate 28-fold.
//
// Measured on production 2026-11-24: 3 denied_spike findings reported as
// "3 alert(s) in 28 days ... expected 28.00, p=2.8e-9, drifted_low" — a
// detector flagged as having nearly stopped while producing ~3/day, which
// scripts/a6Harness.js independently measures at 3.75/day for the shipped
// configuration. The meta-check built to catch a stale rate was reporting a
// fabricated one, and the whole suite was green over it.
// ─────────────────────────────────────────────────────────────────────────────
describe('⛔ rateDrift is given each detector\'s own observation window', () => {
  const DEV = '44444444-4444-4444-8444-444444444444';
  const HOURS = 24 * 28;

  const pool = {
    query: async (sql) => {
      if (/max\(bucket_hour\) AS last_at/.test(sql)) {
        return { rows: [{ device_id: DEV, last_at: new Date(Date.UTC(2026, 10, 24, 7)) }] };
      }
      if (/generate_series/.test(sql)) {
        return {
          rows: Array.from({ length: HOURS }, (_, i) => ({
            device_id: DEV, device_name: 'FW', at: new Date(Date.UTC(2026, 9, 27, i)),
            reported: true, grid_starts_at_birth: false,
          })),
        };
      }
      if (/FROM reporting/.test(sql) || /deny/i.test(sql)) {
        return {
          rows: Array.from({ length: HOURS }, (_, i) => ({
            device_id: DEV, device_name: 'FW', at: new Date(Date.UTC(2026, 9, 27, i)),
            value: 10,
          })),
        };
      }
      return { rows: [] };
    },
  };

  it('device_silent is scored over the GRID window', async () => {
    const { rates } = await anomalyData.gatherAnomalies(pool, { now: NOW, days: 28 });
    assert.equal(rates.device_silent.windowDays, 28,
      'the silence detector walks the whole grid, so its findings span it');
  });

  it('⛔ denied_spike is scored over the JUDGE window, not the grid window', async () => {
    const { rates } = await anomalyData.gatherAnomalies(pool, { now: NOW, days: 28 });
    assert.equal(rates.denied_spike.windowDays, 1,
      'detectSpike judges only the last 24h, so dividing its findings by the '
      + '28-day grid understates the rate 28-fold — which is exactly how a '
      + 'detector producing ~3/day was reported as drifted_low at p=2.8e-9');
  });

  it('⛔ the two windows are NOT the same number', async () => {
    // The bug was one variable used twice. Pin the relation, not the values.
    const { rates } = await anomalyData.gatherAnomalies(pool, { now: NOW, days: 28 });
    assert.notEqual(rates.denied_spike.windowDays, rates.device_silent.windowDays,
      'passing one window for both detectors is the defect');
  });

  it('the judge window is DERIVED, so overriding it moves the divisor', async () => {
    const { rates } = await anomalyData.gatherAnomalies(pool,
      { now: NOW, days: 28, judgeWindowHours: 48 });
    assert.equal(rates.denied_spike.windowDays, 2,
      'a hardcoded divisor would survive a changed judge window');
  });
});
