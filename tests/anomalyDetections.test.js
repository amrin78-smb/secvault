'use strict';

// tests/anomalyDetections.test.js
//
// Pins A6 stage 2 — the detectors, their registration gate, and the toggle.
//
// ⛔ THE CASES WEIGHTED HEAVIEST ARE THE "WE COULD NOT MEASURE THIS" ONES.
// A detector's dangerous failure is not a crash, it is silence that reads as
// health: a thin baseline reported as "nothing wrong", a device that never
// reported called "stopped", or an alert type nobody can subscribe to.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const a = require('../lib/engines/anomalyDetections');
const dispatch = require('../lib/engines/notificationDispatch');

const H = (n, reported, from = 0) =>
  Array.from({ length: n }, (_, i) => ({ at: new Date(Date.UTC(2026, 9, 1, from + i)), reported }));

function series(weeks, { spikeFromEnd, spikeLen = 4, mag = 9000 } = {}) {
  const rows = [];
  const start = Date.UTC(2026, 5, 1);
  const total = 24 * 7 * weeks;
  for (let h = 0; h < total; h += 1) {
    const at = new Date(start + h * 3600e3);
    const hod = at.getUTCHours();
    let v = Math.max(50, Math.round(1000 + 900 * Math.sin(((hod - 6) / 24) * 2 * Math.PI)));
    if (spikeFromEnd !== undefined && h >= total - spikeFromEnd && h < total - spikeFromEnd + spikeLen) v += mag;
    rows.push({ at, value: v });
  }
  return rows;
}

describe('⛔ a detector cannot ship without a MEASUREMENT', () => {
  it('every registered detector carries measured evidence', () => {
    // analytics-proposal.md records a method being falsified on this very data
    // (A7: Iglewicz-Hoaglin at 3.5 flagged 17.3% of change-free days). The rule
    // that follows is that a threshold is measured, never chosen by taste.
    for (const [key, d] of Object.entries(a.DETECTORS)) {
      assert.ok(d.evidence, `${key} has no evidence`);
      assert.equal(typeof d.evidence.alertsPerDay, 'number', `${key} has no measured alert rate`);
      assert.ok(d.evidence.measuredOn, `${key} does not say when it was measured`);
      assert.ok(d.evidence.method && d.evidence.method.length > 40, `${key} does not say how`);
    }
  });

  it('⛔ registering an unmeasured detector THROWS', () => {
    assert.throws(() => a.assertRegisteredDetector('no_such_detector'), /no measured evidence/);
  });

  it('⛔ the two detectors MEASURED AND REFUSED are not registered', () => {
    // total-events spike: 6.91 alerts/day. vpn auth burst: 3.32/day AND
    // trending ~7x over the window, which makes a STATIC baseline the wrong
    // instrument rather than a mistuned one. Both are results, not gaps.
    assert.ok(!a.DETECTORS.events_spike, 'total-events spike measured at 6.91/day must not ship');
    assert.ok(!a.DETECTORS.vpn_auth_burst, 'vpn auth burst measured at 3.32/day and trending must not ship');
    assert.deepEqual(Object.keys(a.DETECTORS).sort(), ['denied_spike', 'device_silent']);
  });

  it('the recorded alert rates are the ones actually measured', () => {
    assert.equal(a.EVIDENCE.device_silent.alertsPerDay, 0.074);
    assert.equal(a.EVIDENCE.denied_spike.alertsPerDay, 1.0);
    assert.equal(a.EVIDENCE.denied_spike.sensitivity, 1.0);
  });
});

describe('⛔ device silent — absence is the signal', () => {
  it('a sustained silence is reported, an isolated hour is not', () => {
    const mix = [...H(5, true), ...H(4, false, 5), ...H(5, true, 9), ...H(1, false, 14), ...H(3, true, 15)];
    const r = a.detectSilence(mix, { minHours: 2 });
    assert.equal(r.state, 'measured');
    assert.equal(r.runs.length, 1, 'the single silent hour must not alert');
    assert.equal(r.runs[0].hours, 4);
  });

  it('⛔ a device that NEVER reported is no_data, NOT silent', () => {
    // "Stopped logging" about a firewall that never started sends someone to
    // look for an outage that never happened. It is an uncollected device,
    // which is a different fact with a different owner.
    const r = a.detectSilence(H(48, false));
    assert.equal(r.state, 'no_data');
    assert.deepEqual(r.runs, []);
    assert.match(r.reason, /never reported/);
  });

  it('a silence still in progress at the end of the window counts', () => {
    // The one most worth reporting — it is happening now.
    const r = a.detectSilence([...H(10, true), ...H(5, false, 10)], { minHours: 2 });
    assert.equal(r.runs.length, 1);
    assert.equal(r.runs[0].hours, 5);
  });

  it('malformed input never throws', () => {
    for (const bad of [null, undefined, 'x', [null, undefined], []]) {
      const r = a.detectSilence(bad);
      assert.ok(r && Array.isArray(r.runs));
    }
  });
});

describe('⛔ denied spike — the baseline is HISTORY, the window is judged', () => {
  it('a clean recent window produces nothing', () => {
    const r = a.detectSpike(series(20));
    assert.equal(r.state, 'measured');
    assert.equal(r.runs.length, 0);
  });

  it('⛔ a SUSTAINED anomaly does not hide itself in its own baseline', () => {
    // Measured: a 4h spike does not self-mask (bucket threshold moved 149->146,
    // i.e. not at all, because 4 hours among ~140 observations cannot shift a
    // 90th percentile). But a LONG one would, and that is the event most worth
    // catching — so the baseline excludes the judged window entirely.
    for (const len of [4, 12, 20]) {
      const r = a.detectSpike(series(20, { spikeFromEnd: 22, spikeLen: len }));
      assert.equal(r.state, 'measured', `${len}h`);
      assert.ok(r.runs.length >= 1, `${len}h anomaly not detected`);
      assert.ok(Math.max(...r.runs.map((x) => x.hours)) >= Math.min(len, 22),
        `${len}h anomaly detected only partially`);
    }
  });

  it('\u26d4 a LARGE judged window cannot mask itself — the boundary is (1-q)', () => {
    // The first version of this test could not fail: a 20h anomaly spread over
    // 20 hour-of-day buckets adds ~1 observation each among ~140, which cannot
    // shift a 90th percentile either way, so the split made no difference and
    // removing it passed. A guard that cannot fire.
    //
    // Measured boundary: masking begins once the anomaly exceeds (1-q) of a
    // bucket's observations, because at that point the q-th percentile falls
    // INSIDE the anomalous points and they stop exceeding it. At q=0.9:
    //   5%, 9%  -> still found      11% -> FRAGMENTS (7 runs, not 1)
    //   15%, 25% -> fully MASKED
    // The default 24h window against 28 days of history is 3.6%, so the default
    // is safe by a wide margin — but a caller raising judgeWindowHours is not,
    // and that is what this pins.
    const totalH = 24 * 70;
    const anomH = Math.round(totalH * 0.25);
    const rows = [];
    const start = Date.UTC(2026, 5, 1);
    for (let h = 0; h < totalH; h += 1) {
      const at = new Date(start + h * 3600e3);
      const hod = at.getUTCHours();
      let v = Math.max(50, Math.round(1000 + 900 * Math.sin(((hod - 6) / 24) * 2 * Math.PI)));
      if (h >= totalH - anomH) v += 1200;
      rows.push({ at, value: v });
    }
    const r = a.detectSpike(rows, { judgeWindowHours: anomH });
    assert.equal(r.state, 'measured');
    assert.ok(r.runs.length >= 1,
      'a sustained anomaly filling a quarter of the window was NOT found — it was masked by '
      + 'its own baseline, which is what excluding the judged window exists to prevent');
    assert.ok(Math.max(...r.runs.map((x) => x.hours)) > anomH * 0.5,
      'the anomaly was found only in fragments, which is the partial form of the same masking');
  });

  it('⛔ too little history is INSUFFICIENT, never "nothing found"', () => {
    const r = a.detectSpike(series(20).slice(-24));
    assert.equal(r.state, 'insufficient_baseline');
    assert.deepEqual(r.runs, []);
    assert.ok(r.reason, 'it must say why');
  });

  it('⛔ no data at all is its own state', () => {
    assert.equal(a.detectSpike([]).state, 'no_data');
    assert.equal(a.detectSpike(null).state, 'no_data');
  });

  it('a run carries the NAMED THRESHOLD, not a score', () => {
    // roadmap.md's rule. "4,812 denied against a ceiling of 1,230 over 27
    // observations" is checkable; "anomaly score 3.7" is not.
    const r = a.detectSpike(series(20, { spikeFromEnd: 20, spikeLen: 6 }));
    const run = r.runs[0];
    assert.ok(run, 'no run produced');
    assert.equal(typeof run.threshold, 'number');
    assert.equal(typeof run.peak, 'number');
    assert.equal(typeof run.observations, 'number');
    assert.ok(!('score' in run));
    const text = a.describeSpike(run, 'FW-1');
    assert.match(text, /percentile/);
    assert.match(text, /\d/);
    assert.ok(!/score/i.test(text), 'the sentence must not offer a score');
  });
});

describe('⛔ the 5% margin floor, and the hour it reports', () => {
  const build = (judged) => {
    // 20 weeks of flat history at 1000, then a judged window we control.
    const rows = []; const start = Date.UTC(2026, 5, 1);
    for (let h = 0; h < 24 * 7 * 20; h += 1) rows.push({ at: new Date(start + h * 3600e3), value: 1000 });
    const base = rows.length;
    judged.forEach((v, i) => rows.push({ at: new Date(start + (base + i) * 3600e3), value: v }));
    return rows;
  };

  it('⛔ a TRIVIAL exceedance is not reported', () => {
    // Production fired on "2,897 against a ceiling of 2,897, 0.0% above it" —
    // an exceedance of under one event. That reads as an alert on empty air,
    // and is how an operator learns to mute the channel.
    const r = a.detectSpike(build([1001, 1001, 1001, 1001, 1001, 1001]), { judgeWindowHours: 6 });
    assert.equal(r.state, 'measured');
    assert.deepEqual(r.runs, [], 'a 0.1% exceedance must not be reported');
  });

  it('a REAL exceedance still is', () => {
    const r = a.detectSpike(build([1400, 1400, 1400, 1400, 1400, 1400]), { judgeWindowHours: 6 });
    assert.equal(r.runs.length, 1);
    assert.ok(r.runs[0].exceedancePct >= a.SPIKE_MIN_MARGIN_PCT);
  });

  it('⛔ the floor keeps a GAP to the smallest anomaly actually measured', () => {
    // Planted anomalies the stage-1 harness detects carry a MINIMUM margin of
    // 10.9%. A floor at or above that starts discarding real events — which is
    // why 10% was refused despite cutting more noise (10/32 runs vs 20/32).
    assert.ok(a.SPIKE_MIN_MARGIN_PCT < 10.9,
      'the floor must stay below the smallest measured real anomaly margin');
    assert.ok(a.SPIKE_MIN_MARGIN_PCT > 0, 'a floor of 0 is no floor');
  });

  // A history where buckets DIFFER, so the largest-value hour and the
  // largest-exceedance hour are different hours. The flat fixture above cannot
  // tell them apart — every bucket shares one threshold there, so reporting by
  // value and by exceedance give the same answer and the mutation escapes.
  const skewed = () => {
    const rows = []; const start = Date.UTC(2026, 5, 1);
    // hour 11 is a QUIET hour (~1000); hours 12 and 13 are BUSY (~10000), with
    // enough spread that the median and the 90th percentile cannot coincide.
    // \u26d4 24 weeks, not 20. selectGrain UPGRADES to hour_of_week once there are
    // enough weeks, and each of those buckets then needs 20 observations of its
    // own. At 20 weeks the trim below removes the final partial week, leaving
    // the three judged buckets on 19 — so they came back `insufficient_baseline`,
    // were never anomalous, and the fixture produced no run at all. The fixture
    // was sitting exactly on the boundary it was meant to be testing past.
    for (let h = 0; h < 24 * 7 * 24; h += 1) {
      const at = new Date(start + h * 3600e3); const hod = at.getUTCHours();
      const base = (hod === 12 || hod === 13) ? 10000 : 1000;
      rows.push({ at, value: base + ((h * 37) % 100) });
    }
    // Judged window: the BUSY hours barely clear their high ceiling, the QUIET
    // hour clears its low one by 200%. Largest VALUE is a busy hour; largest
    // EXCEEDANCE is the quiet one.
    // \u26d4 Trim so the series ENDS at hour 13 — otherwise the modified hours are
    // not the last three and fall outside the judged window entirely, which is
    // how the first draft of this fixture produced zero runs.
    while (rows.length && rows[rows.length - 1].at.getUTCHours() !== 13) rows.pop();
    const n = rows.length;
    rows[n - 3].value = 3000;   // hour 11, quiet bucket  -> ~200% over
    rows[n - 2].value = 11000;  // hour 12, busy bucket   -> ~10% over
    rows[n - 1].value = 11000;  // hour 13, busy bucket   -> ~10% over
    return rows;
  };

  it('⛔ the hour REPORTED is the largest EXCEEDANCE, not the largest value', () => {
    const r = a.detectSpike(skewed(), { judgeWindowHours: 3 });
    assert.equal(r.state, 'measured');
    assert.equal(r.runs.length, 1);
    const run = r.runs[0];
    assert.ok(run.peak < 11000,
      `reported the biggest VALUE (${run.peak}) instead of the biggest exceedance — `
      + 'the alert then reads as a large number barely over a large ceiling, which is '
      + 'the "16,276 vs 15,216, 7%" shape production produced for a 17% event');
    assert.ok(run.exceedancePct > 100, `expected the ~200% hour, got ${run.exceedancePct}%`);
  });

  it('⛔ the margin is computed from the THRESHOLD, never the median', () => {
    const r = a.detectSpike(skewed(), { judgeWindowHours: 3 });
    const run = r.runs[0];
    assert.ok(run.median !== run.threshold, 'fixture must separate median from threshold');
    const fromThreshold = ((run.peak - run.threshold) / run.threshold) * 100;
    assert.ok(Math.abs(fromThreshold - run.exceedancePct) < 1e-9,
      'the printed margin must be the peak over the THRESHOLD — the threshold is what it '
      + 'cleared, and a margin over the median describes a different, larger claim');
  });

  it('⛔ the printed margin is derived from the printed PAIR', () => {
    // Each hour is judged against its OWN bucket, so the biggest-VALUE hour can
    // be the one that barely cleared while another cleared a lower threshold by
    // far more. Live: by value "16,276 vs 15,216, 7% above"; by exceedance the
    // same event reads "13,583 vs 11,574, 17% above" — a smaller number that
    // describes the event better. If the pair and the margin disagree the
    // sentence contradicts itself.
    const r = a.detectSpike(build([2000, 1400, 1400]), { judgeWindowHours: 3 });
    assert.equal(r.runs.length, 1);
    const run = r.runs[0];
    const derived = ((run.peak - run.threshold) / run.threshold) * 100;
    assert.ok(Math.abs(derived - run.exceedancePct) < 1e-9);
    assert.match(a.describeSpike(run, 'FW'), new RegExp(`${Math.round(run.exceedancePct)}% above it`));
  });
});

describe('\u26d4 the alert sentence never understates what fired', () => {
  it('a sub-1% margin is NOT printed as "0% above"', () => {
    // Measured on the live fleet: margins are median 7% but range from 0.4% to
    // 1025%. A run exists only because the value EXCEEDED the threshold, so a
    // margin rounding to zero reads as an alert fired on nothing — which is how
    // an operator learns to ignore a channel.
    const text = a.describeSpike(
      { peak: 2897, threshold: 2885, observations: 27, hours: 3 }, 'FW-1'
    );
    assert.ok(!/\b0% above/.test(text), `printed a zero margin: ${text}`);
    assert.match(text, /0\.4% above it/);
  });

  it('an ordinary margin stays a whole number', () => {
    const text = a.describeSpike(
      { peak: 16276, threshold: 15216, observations: 27, hours: 3 }, 'FW-2'
    );
    assert.match(text, /7% above it/);
  });

  it('a run with no threshold still produces a sentence, without inventing one', () => {
    const text = a.describeSpike({ peak: null, threshold: null, hours: 4 }, 'FW-3');
    assert.match(text, /4 consecutive hours/);
    assert.ok(!/%/.test(text), 'it must not imply a margin it does not have');
  });
});

describe('⛔ the toggle gates DISPATCH, and both registries must agree', () => {
  it('each detector is its own alert type', () => {
    // Separate types so muting a noisy detector cannot mute a firewall going
    // dark. Deliberately the OPPOSITE call from work_act_now, which collapses
    // twelve sources into one.
    assert.deepEqual(a.ANOMALY_ALERT_TYPES.sort(), ['anomaly_denied_spike', 'anomaly_device_silent']);
    for (const t of a.ANOMALY_ALERT_TYPES) {
      assert.ok(dispatch.ALERT_TYPES.includes(t), `${t} is not dispatchable`);
    }
  });

  it('⛔ the Settings UI lists every dispatchable type, or it cannot be switched on', () => {
    // The panel keeps its own literal (client ESM vs CommonJS), the same
    // dual-registry convention as vendorMeta <-> ADAPTERS. Drift here does not
    // error — it makes a detector permanently unsubscribable, so it runs,
    // finds things, and nothing is ever sent.
    const ui = fs.readFileSync(
      path.join(__dirname, '..', 'components', 'settings', 'NotificationsPanel.js'), 'utf8'
    );
    const m = ui.match(/const ALERT_TYPES = \[([\s\S]*?)\];/);
    assert.ok(m, 'could not find ALERT_TYPES in NotificationsPanel');
    const uiTypes = [...m[1].matchAll(/'([a-z_]+)'/g)].map((x) => x[1]);
    const missing = dispatch.ALERT_TYPES.filter((t) => !uiTypes.includes(t));
    assert.deepEqual(missing, [], `dispatchable but not offered in Settings: ${missing.join(', ')}`);

    const labels = ui.match(/const ALERT_TYPE_LABEL = \{([\s\S]*?)\n\};/);
    assert.ok(labels, 'could not find ALERT_TYPE_LABEL');
    for (const t of a.ANOMALY_ALERT_TYPES) {
      assert.ok(labels[1].includes(`${t}:`), `${t} has no human label in Settings`);
    }
  });

  it('⛔ every dispatchable type has a fetcher', () => {
    // A type with no fetcher throws inside the per-type try, which logs and
    // silently skips that type FOR EVER. notificationDispatch asserts this at
    // load; this pins that the assertion exists and is reached.
    const src = fs.readFileSync(
      path.join(__dirname, '..', 'lib', 'engines', 'notificationDispatch.js'), 'utf8'
    );
    assert.match(src, /has no fetcher in OPEN_ITEM_FETCHERS/);
  });
});
