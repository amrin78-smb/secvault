// tests/collapseSubsumesSilence.test.js
//
// ⛔ WHY THIS FILE EXISTS. Registering `volume_collapse` without consulting it
// from the silence loop would have made TFM-MH's findings go from 38 to 39 — a
// net ADDITION, when the whole measured case for the detector is that it
// REPLACES 38 wrong findings with one correct one. Measured on production
// 2026-11-24: 42 anomaly findings fleet-wide became 5, and the collapsed
// firewall's 39 silence runs became one sentence.
//
// ⛔ AND THE SUPPRESSION IS EXACTLY THE SHAPE OF WIRING THIS REPO HAS WATCHED GO
// UNTESTED. CLAUDE.md records `getThreatCoverage()` awaited into a variable a
// widget never referenced, and a `corpusAdvance()` verdict computed and consulted
// by nobody — in both cases every arm of the logic was pinned and nothing
// asserted that anyone used it. So these tests assert the OUTCOME (which
// findings come out) rather than the mechanism.

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const anomalyData = require('../lib/engines/anomalyDetectionsData');

const COLLAPSED = '11111111-1111-4111-8111-111111111111';
const HEALTHY = '22222222-2222-4222-8222-222222222222';
const NOW = new Date(Date.UTC(2026, 10, 24, 12));
const GRID_HOURS = 24 * 28;

/**
 * @param {object} o
 * @param {boolean} o.withDaily  false => the daily read returns nothing, which
 *   is the FAIL-OPEN case: nothing is suppressed and device_silent behaves
 *   exactly as it did before this detector existed.
 */
function stubPool({ withDaily = true } = {}) {
  return {
    query: async (sql) => {
      // ⛔ MATCHED BEFORE /generate_series/, because loadDailyVolumes ALSO
      // contains generate_series — so an order-insensitive stub would hand the
      // daily loader the hourly grid's rows and this fixture would quietly
      // test nothing.
      if (/fleet_hours/.test(sql)) {
        if (!withDaily) return { rows: [] };
        const rows = [];
        const push = (device_id, device_name, day, events) => rows.push({
          device_id, device_name, day, events, judgeable: true,
        });
        for (let i = 0; i < 45; i += 1) {
          const day = `2026-10-${String(i + 1).padStart(2, '0')}`;
          // The collapsed firewall: a long healthy level, then a tiny one.
          push(COLLAPSED, 'COLLAPSED-FW', day, i < 40 ? 1_000_000 : 30);
          // The healthy one stays level, so it must NOT be suppressed.
          push(HEALTHY, 'HEALTHY-FW', day, 1_000_000);
        }
        return { rows };
      }
      if (/max\(bucket_hour\) AS last_at/.test(sql)) {
        return {
          rows: [
            { device_id: COLLAPSED, last_at: new Date(Date.UTC(2026, 10, 24, 7)) },
            { device_id: HEALTHY, last_at: new Date(Date.UTC(2026, 10, 24, 7)) },
          ],
        };
      }
      if (/generate_series/.test(sql)) {
        const rows = [];
        for (let i = 0; i < GRID_HOURS; i += 1) {
          const at = new Date(Date.UTC(2026, 9, 27, i));
          // A 3-hour gap every day => many separate silence runs, which is the
          // shape a dribbling firewall really produces.
          const gap = (i % 24) < 3;
          rows.push({ device_id: COLLAPSED, device_name: 'COLLAPSED-FW', at, reported: !gap });
          rows.push({ device_id: HEALTHY, device_name: 'HEALTHY-FW', at, reported: !gap });
        }
        return { rows };
      }
      return { rows: [] };
    },
  };
}

const silenceFor = (findings, id) => findings.filter(
  (f) => f.detector === 'device_silent' && f.deviceId === id
);

describe('⛔ a collapsed firewall\'s silence runs belong to the collapse finding', () => {
  it('the collapsed device raises ONE collapse finding and NO silence findings', async () => {
    const { findings } = await anomalyData.gatherAnomalies(stubPool(), { now: NOW });
    const collapse = findings.filter((f) => f.detector === 'volume_collapse');
    assert.equal(collapse.length, 1, 'exactly one collapse finding');
    assert.equal(collapse[0].deviceId, COLLAPSED);
    assert.equal(silenceFor(findings, COLLAPSED).length, 0,
      'its gaps are symptoms of the collapse and must not be separate findings');
  });

  it('⛔ the absorbed runs are COUNTED, and the count is the real one', async () => {
    // The number must equal what device_silent WOULD have reported, or the
    // sentence under-states how badly the firewall is reporting.
    const open = await anomalyData.gatherAnomalies(stubPool({ withDaily: false }), { now: NOW });
    const wouldHave = silenceFor(open.findings, COLLAPSED).length;
    assert.ok(wouldHave > 5, `fixture should produce many runs, produced ${wouldHave}`);

    const { findings } = await anomalyData.gatherAnomalies(stubPool(), { now: NOW });
    const collapse = findings.find((f) => f.detector === 'volume_collapse');
    assert.equal(collapse.supersededSilenceRuns, wouldHave,
      'every suppressed run must be accounted for on the finding that replaced it');
    assert.match(collapse.summary, new RegExp(`${wouldHave} separate silence runs`),
      'and stated in words, or the operator cannot see the firewall reports in gaps');
  });

  it('⛔ a HEALTHY firewall is never suppressed', async () => {
    // Without this the test above is satisfied by suppressing everything.
    const { findings } = await anomalyData.gatherAnomalies(stubPool(), { now: NOW });
    assert.ok(silenceFor(findings, HEALTHY).length > 0,
      'a firewall with gaps but no volume collapse must still raise silence findings');
  });

  it('⛔ FAILS TOWARD MORE FINDINGS: no daily data suppresses nothing', async () => {
    // The read is deliberately not wrapped in a try/catch — a throw reaches the
    // dispatcher's per-type catch, which skips the reconcile. But an EMPTY
    // result must leave device_silent behaving exactly as it did before this
    // detector existed, never silently quieter.
    const { findings } = await anomalyData.gatherAnomalies(
      stubPool({ withDaily: false }), { now: NOW }
    );
    assert.equal(findings.filter((f) => f.detector === 'volume_collapse').length, 0);
    assert.ok(silenceFor(findings, COLLAPSED).length > 0,
      'with no collapse verdict available, the silence findings must all be raised');
  });

  it('⛔ the device is still counted MEASURED for device_silent', async () => {
    // Suppression hides the FINDING, never the MEASUREMENT. If the device fell
    // out of the coverage denominator the panel would report a collapsed
    // firewall as unjudged — which is the hole v2.237.3 closed.
    const { states } = await anomalyData.gatherAnomalies(stubPool(), { now: NOW });
    assert.equal(states.device_silent.measured, 2,
      'both firewalls were judged by device_silent, whatever happened to the findings');
    assert.equal(states.volume_collapse.measured, 2);
  });

  it('⛔ the natural key is the ONSET DAY, so the alert cannot churn', async () => {
    // Keyed on today the dispatcher would resolve and re-raise this every day
    // for as long as the firewall stayed collapsed — the churn v2.228.10 fixed
    // for silence runs, reachable here by simply waiting.
    const { findings } = await anomalyData.gatherAnomalies(stubPool(), { now: NOW });
    const c = findings.find((f) => f.detector === 'volume_collapse');
    assert.equal(c.naturalKey, `anomaly_volume_collapse:${COLLAPSED}:${c.onsetDay}`);
    assert.match(c.onsetDay, /^2026-\d\d-\d\d$/);
    assert.ok(c.onsetDay < '2026-11-24', 'the onset is in the past, not today');
  });
});

describe('⛔ the collapse baseline window is NOT the detector window', () => {
  it('it is materially longer, and that is what stops the finding clearing itself', () => {
    // ⛔ A 28-day trailing baseline makes a collapse DISAPPEAR while the firewall
    // is still collapsed: once the pre-collapse days fall out of the window the
    // baseline IS the collapsed level. Measured — TFM-MH fell on 2026-11-08, so
    // a 28-day baseline would stop reporting it around 2026-12-06. The same
    // shape as the defect v2.230.0 fixed for device_silent, where a device dark
    // for LONGER than the window raised nothing.
    //
    // ⛔ A LONGER WINDOW DEFERS IT, IT DOES NOT REMOVE IT. The baseline is a
    // median, so it flips once collapsed days outnumber healthy ones in the
    // retained history — at 180 days, after roughly 90. Only a baseline
    // anchored to a stored pre-onset period would fix it outright.
    assert.ok(anomalyData.COLLAPSE_LOOKBACK_DAYS >= 4 * anomalyData.LOOKBACK_DAYS,
      `collapse baseline is ${anomalyData.COLLAPSE_LOOKBACK_DAYS} days against a `
      + `${anomalyData.LOOKBACK_DAYS}-day detector window — too short to outlive a collapse`);
  });

  it('the loader defaults to it rather than to the detector window', () => {
    // Mechanism, deliberately: the default lives in the signature, so an
    // outcome test cannot see which constant it came from.
    const src = require('fs').readFileSync(
      require('path').join(__dirname, '..', 'lib', 'engines', 'anomalyDetectionsData.js'), 'utf8'
    );
    assert.match(src, /loadDailyVolumes\(pool, \{ days = COLLAPSE_LOOKBACK_DAYS \} = \{\}\)/,
      'defaulting this to LOOKBACK_DAYS reinstates the self-clearing collapse');
  });
});
