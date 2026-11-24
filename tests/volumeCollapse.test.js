// tests/volumeCollapse.test.js
//
// ⛔ WHAT THIS DETECTOR IS FOR. `device_silent` asks only "did ANY event arrive
// this hour", so a firewall whose syslog falls by 99.999% and keeps dribbling
// is invisible to it. Measured on production 2026-11-24: TFM-MH went from
// ~5.9M events/day to ~30 on 2026-11-08 and was still dark 16 days later,
// having produced nothing but scattered 2-hour silence runs that read as noise
// while every reachability signal stayed green (its management collection
// still succeeds).
//
// ⛔ IT IS NOT REGISTERED, AND A TEST BELOW PINS THAT. `assertRegisteredDetector`
// requires a measured alert rate AND sensitivity; v2.237.6 is the argument for
// not guessing either, since the same configuration of an existing detector
// read 89% at a 28-plant sample and 94% at 375.

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const a = require('../lib/engines/anomalyDetections');
const { detectVolumeCollapse: detect, DETECTOR_STATES: S } = a;

const day = (i) => `2026-${String(1 + Math.floor(i / 28)).padStart(2, '0')}-${String((i % 28) + 1).padStart(2, '0')}`;

/** n days at `level`, then m days at `after`. */
function series(n, level, m = 0, after = 0, opts = {}) {
  const rows = [];
  for (let i = 0; i < n + m; i += 1) {
    rows.push({
      day: day(i),
      events: i < n ? level : after,
      ...(opts.judgeableFrom !== undefined && i < opts.judgeableFrom ? { judgeable: false } : {}),
    });
  }
  return rows;
}

describe('⛔ a volume collapse is detected where silence is not', () => {
  it('the TFM-MH shape: 5.9M/day for weeks, then ~30/day', () => {
    const r = detect(series(40, 5_900_000, 16, 30));
    assert.equal(r.state, S.MEASURED);
    assert.equal(r.collapsed, true, 'a 99.999% fall must be detected');
    assert.ok(r.baseline > 1_000_000);
    assert.ok(r.recent < 100);
    assert.ok(r.onsetDay, 'the onset must be reported so the alert key is stable');
  });

  it('a steady firewall is not collapsed', () => {
    const r = detect(series(40, 5_900_000, 10, 5_800_000));
    assert.equal(r.state, S.MEASURED);
    assert.equal(r.collapsed, false);
    assert.equal(r.onsetDay, null);
  });

  it('⛔ ordinary variation is not a collapse', () => {
    // Halving is a big change and emphatically not 99%.
    assert.equal(detect(series(40, 1_000_000, 10, 500_000)).collapsed, false);
    assert.equal(detect(series(40, 1_000_000, 10, 100_000)).collapsed, false);
    // 99.5% down clears the 99% bar.
    assert.equal(detect(series(40, 1_000_000, 10, 5_000)).collapsed, true);
  });

  it('⛔ ONE bad day is not a collapse — that is maintenance', () => {
    const rows = series(40, 1_000_000);
    rows.push({ day: day(40), events: 10 });
    assert.equal(detect(rows).collapsed, false,
      'a single-day outage must not alert; the sustain window exists for it');
    rows.push({ day: day(41), events: 10 });
    assert.equal(detect(rows).collapsed, true, 'two days is the declared sustain');
  });
});

describe('⛔ the states it refuses to judge', () => {
  it('a firewall that never reported is no_data, never collapsed', () => {
    const r = detect(series(40, 0));
    assert.equal(r.state, S.NO_DATA);
    assert.equal(r.collapsed, false);
    assert.match(r.reason, /never reported/);
  });

  it('too little history is insufficient_baseline, never a verdict', () => {
    const r = detect(series(5, 1_000_000, 2, 10));
    assert.equal(r.state, S.INSUFFICIENT_BASELINE);
    assert.equal(r.collapsed, false);
    assert.match(r.reason, /judgeable days/);
  });

  it('an empty or junk series yields no_data, never a crash or a false verdict', () => {
    for (const input of [[], null, undefined, 'nonsense', [{}], [{ day: 'x', events: 'abc' }]]) {
      const r = detect(input);
      assert.equal(r.collapsed, false, `input ${JSON.stringify(input)} produced a verdict`);
      assert.equal(r.state, S.NO_DATA);
    }
  });

  it('⛔ a baseline of ZERO is not a baseline — no collapse from nothing', () => {
    // Reachable at sustain >= 3 on a device that mostly does not report: the
    // history median is 0, the recent median is 0, and `0 <= 0 * 0.01` is TRUE.
    // Without the `base <= 0` guard such a firewall is reported as having
    // collapsed from nothing to nothing — a confident verdict over no evidence,
    // which is the shape this whole engine exists to refuse.
    const rows = [];
    for (let i = 0; i < 20; i += 1) rows.push({ day: day(i), events: i < 15 ? 0 : 1_000_000 });
    rows.push({ day: day(20), events: 0 }, { day: day(21), events: 0 }, { day: day(22), events: 10 });
    const r = detect(rows, { sustainDays: 3 });
    assert.equal(r.collapsed, false,
      'a device whose own history medians to zero has no level to have fallen from');
  });

  it('⛔ a FULLY DARK firewall is device_silent\'s, not this detector\'s', () => {
    // Two detectors reporting one event is the duplicate-vocabulary problem.
    const r = detect(series(40, 1_000_000, 3, 0));
    assert.equal(r.collapsed, false,
      'zero across the whole sustain window belongs to device_silent');
  });
});

describe('⛔ a day the FLEET was not collecting is excluded, never zeroed', () => {
  it('a collector outage does not flag a healthy firewall', () => {
    // Without this guard a 2-day deploy gap flags every device at once.
    const rows = series(40, 1_000_000);
    rows.push({ day: day(40), events: 0, judgeable: false });
    rows.push({ day: day(41), events: 0, judgeable: false });
    const r = detect(rows);
    assert.equal(r.collapsed, false,
      'unjudgeable days must be dropped from the recent window, not counted as zero');
  });

  it('⛔ unjudgeable zeros in HISTORY must not hide a real collapse', () => {
    // This is the dangerous direction. 25 spurious zeros (a long collector
    // outage) counted as real would drag the baseline median to 0, `base <= 0`
    // would return no verdict, and a firewall that genuinely collapsed would
    // be reported healthy — a failed read recorded as a fact, in the detector
    // built to catch exactly that.
    const rows = series(40, 1_000_000);
    for (let i = 0; i < 25; i += 1) rows[i] = { ...rows[i], events: 0, judgeable: false };
    rows.push({ day: day(40), events: 10 }, { day: day(41), events: 10 });
    const r = detect(rows);
    assert.equal(r.state, S.MEASURED);
    assert.equal(r.collapsed, true,
      'the 15 real days must carry the baseline; counting the excluded zeros '
      + 'drives the median to 0 and silently suppresses the finding');
    assert.ok(r.baseline > 100_000, `baseline was ${r.baseline}, so zeros leaked in`);
  });
});

describe('⛔ the onset is reported so the alert cannot churn', () => {
  it('onset stays put as the collapse continues', () => {
    // Keyed on "today" the dispatcher resolves and re-raises daily for as long
    // as the firewall stays dark — the churn v2.228.10 fixed for silence runs,
    // reachable here by simply waiting.
    const base = series(40, 1_000_000, 5, 20);
    const later = series(40, 1_000_000, 12, 20);
    const a1 = detect(base);
    const a2 = detect(later);
    assert.equal(a1.collapsed, true);
    assert.equal(a2.collapsed, true);
    assert.equal(a1.onsetDay, a2.onsetDay,
      'the onset must not move as the collapse ages, or the alert key churns');
  });
});

describe('⛔ it is NOT registered until it is measured', () => {
  it('absent from DETECTORS', () => {
    assert.ok(!a.DETECTORS.volume_collapse,
      'registering before scripts/a6Harness.js has measured an alert rate AND a '
      + 'sensitivity is the thing assertRegisteredDetector exists to prevent');
    assert.deepEqual(Object.keys(a.DETECTORS).sort(), ['denied_spike', 'device_silent']);
  });

  it('absent from the dispatched alert types', () => {
    assert.ok(!a.ANOMALY_ALERT_TYPES.includes('anomaly_volume_collapse'),
      'an unmeasured detector must not reach a notification channel');
  });

  it('has no EVIDENCE entry', () => {
    assert.ok(!a.EVIDENCE.volume_collapse);
  });
});
