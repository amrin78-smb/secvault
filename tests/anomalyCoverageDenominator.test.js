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
