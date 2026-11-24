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
  });

  it('⛔ the window is a LENGTH, not a run — a MAJORITY of it must be down', () => {
    // ⛔ THIS PINS WHAT THE CODE DOES, AFTER A TEST PASSED FOR THE WRONG REASON.
    // The old version of this asserted "two days is the declared sustain" and
    // went on passing when COLLAPSE_SUSTAIN_DAYS moved from 2 to 3 — because the
    // verdict is the window's MEDIAN, so two down days out of three already
    // carry it. The constant's own comment said "consecutive" and was wrong.
    const base = () => {
      const r = series(40, 1_000_000);
      return r;
    };
    const n = a.COLLAPSE_SUSTAIN_DAYS;
    assert.ok(n >= 3, 'this test is written for a window of at least 3 days');

    // n-1 down days inside an n-day window: a majority, so it fires.
    const majority = base();
    for (let i = 0; i < n - 1; i += 1) majority.push({ day: day(40 + i), events: 10 });
    assert.equal(detect(majority).collapsed, true,
      `${n - 1} down days in a ${n}-day window is a majority and must fire`);

    // Exactly half (rounded down) is NOT a majority, so it must not.
    const minority = base();
    for (let i = 0; i < Math.floor(n / 2); i += 1) minority.push({ day: day(40 + i), events: 10 });
    assert.equal(detect(minority).collapsed, false,
      `${Math.floor(n / 2)} down days in a ${n}-day window is not a majority`);
  });

  it('⛔ a recovery clears it, and takes a majority of the window to do so', () => {
    // The other half of the hysteresis. Without this the majority test above
    // would be satisfied by a detector that never clears.
    const n = a.COLLAPSE_SUSTAIN_DAYS;
    const rows = series(40, 1_000_000);
    for (let i = 0; i < n; i += 1) rows.push({ day: day(40 + i), events: 10 });
    assert.equal(detect(rows).collapsed, true, 'a full window down must fire');
    for (let i = 0; i < n; i += 1) rows.push({ day: day(40 + n + i), events: 1_000_000 });
    assert.equal(detect(rows).collapsed, false,
      'a full window of recovered days must clear the finding');
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

  it('⛔ A ZERO RECENT MEDIAN IS SILENCE, EVEN WHEN THE WINDOW SUM IS NOT ZERO', () => {
    // ⛔ MEASURED ON PRODUCTION 2026-11-24, and this is the shape the first
    // version of the detector got wrong. TFM-RN reported NOTHING from
    // 2026-11-09 to 11-17 (nine days, no rollup rows at all) and recovered on
    // 11-18. Its series therefore holds a window straddling the boundary:
    // [758646, 0, 0]. The old guard asked whether the window SUM was zero --
    // 758,646 is not -- while the verdict used the window MEDIAN, which is.
    //
    // So the guard passed, the detector fired, and the finding said
    // `recent: 0 events/day`: device_silent's exact claim, from the detector
    // built for the case where silence does NOT apply. It also CHURNED,
    // producing two onsets (2026-11-08 and 2026-11-16) for one outage, because
    // the walk-back crossed the dark stretch.
    //
    // The lesson is narrower than "handle zeros": A GUARD MUST TEST THE SAME
    // STATISTIC ITS VERDICT DOES. Two statistics for one question disagree at
    // the boundary, which is the only place the question is hard.
    const rows = [];
    for (let i = 0; i < 40; i += 1) rows.push({ day: day(i), events: 1_580_000 });
    rows.push({ day: day(40), events: 758_646 });
    rows.push({ day: day(41), events: 0 });
    rows.push({ day: day(42), events: 0 });
    const r = detect(rows, { sustainDays: 3 });
    assert.equal(r.collapsed, false,
      'a window whose MEDIAN is zero is a dark device — device_silent\'s finding, '
      + 'not a collapse — however large the one surviving day in it was');
  });

  it('a device DRIBBLING through the window is still this detector\'s', () => {
    // The converse, so the guard above cannot be satisfied by refusing
    // everything: one dark day among two live ones leaves a non-zero median,
    // and a firewall at 500/day against 1.58M has genuinely collapsed while
    // still reporting in enough hours that device_silent cannot see it.
    const rows = [];
    for (let i = 0; i < 40; i += 1) rows.push({ day: day(i), events: 1_580_000 });
    rows.push({ day: day(40), events: 0 });
    rows.push({ day: day(41), events: 500 });
    rows.push({ day: day(42), events: 600 });
    const r = detect(rows, { sustainDays: 3 });
    assert.equal(r.collapsed, true,
      'a non-zero median over the window is a dribble, which is exactly what '
      + 'this detector exists to catch');
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
