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
    assert.deepEqual(Object.keys(a.DETECTORS).sort(),
      ['denied_spike', 'device_silent', 'volume_collapse']);
  });

  it('the recorded alert rates are the ones actually measured', () => {
    assert.equal(a.EVIDENCE.device_silent.alertsPerDay, 0.074);
    // ⛔ RE-MEASURED 2026-11-24 against the REAL detectSpike. The previous
    // pair (1.0 / 1.0) came from a harness that re-implemented the pipeline
    // and omitted detectSpike's 5% margin floor and its per-device grain
    // selection, so it described a detector that does not ship.
    assert.equal(a.EVIDENCE.denied_spike.alertsPerDay, 3.75);
    assert.equal(a.EVIDENCE.denied_spike.sensitivity, 0.94);
  });

  it('⛔ a sensitivity figure is recorded with the SAMPLE it came from', () => {
    // The lesson of 2026-11-24: the same configuration read 89% at n=28 and
    // 94% at n=375, and at n=28 even a perfect score could not have cleared
    // the 90% bar. A bare percentage with no denominator is not a measurement
    // anyone can act on, so the method string has to carry the sample.
    const m = a.EVIDENCE.denied_spike.method;
    assert.match(m, /\b375\b/, 'the planted sample size must be recorded');
    assert.match(m, /CI|confidence|interval/i, 'the interval must be recorded');
  });

  it('⛔ every registered detector states WHEN it was measured', () => {
    // A rate with no date cannot be reviewed, and reviewOverdue cannot fire.
    for (const [key, d] of Object.entries(a.DETECTORS)) {
      assert.match(d.evidence.measuredOn, /^\d{4}-\d{2}-\d{2}$/,
        `${key} has no usable measurement date`);
    }
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
    // ⛔ `null` is the caller SAYING SO, from an unbounded MAX over the
    // permanent rollups. Omitting it is a different answer — see below.
    const r = a.detectSilence(H(48, false), { lastReportedAt: null });
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
    assert.deepEqual(a.ANOMALY_ALERT_TYPES.sort(),
      ['anomaly_denied_spike', 'anomaly_device_silent', 'anomaly_volume_collapse']);
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

// ─── the registered alert rate must be re-testable (roadmap row 28, 2026-11-14) ───
//
// ⛔ WHAT THIS SECTION IS FOR. `assertRegisteredDetector` only ever checked
// that `alertsPerDay`, `measuredOn` and `method` EXIST, so a rate measured on
// one afternoon in October stayed authoritative while the fleet moved. Measured
// against production on 2026-11-14: `device_silent` fired 17 times in 28 days
// against a registered 0.074/day (8.2x, p=9.6e-11), and `denied_spike` fired
// TWICE where 28 were expected (p=2.9e-10) — a drift nobody had even filed,
// because nothing re-measured. The point of these tests is that the meta-check
// REPORTS and never disarms.
describe('anomaly detectors: rate drift is re-tested, not asserted once', () => {
  const NOW = new Date('2026-11-14T00:00:00Z');

  it('catches the measured production drift (device_silent, 17 in 28 days)', () => {
    const r = a.rateDrift('device_silent', 17, 28, NOW);
    assert.equal(r.state, a.RATE_STATES.DRIFTED_HIGH);
    assert.ok(r.ratio > 8 && r.ratio < 8.5, `ratio should be ~8.2, got ${r.ratio}`);
    assert.ok(r.p < 1e-9, `should be decisive, p=${r.p}`);
  });

  // ⛔ THE DANGEROUS DIRECTION. A detector registered as firing daily that
  // produces nothing is indistinguishable from a healthy fleet — this
  // codebase's signature bug in detector form — so it must be a REPORTED
  // state, not silence.
  it('catches a detector that has gone quiet (denied_spike, 0 where 28 expected)', () => {
    const r = a.rateDrift('denied_spike', 0, 28, NOW);
    assert.equal(r.state, a.RATE_STATES.DRIFTED_LOW);
    assert.ok(r.p < 1e-9);
  });

  // ⛔ A RATIO THRESHOLD WOULD FAIL HERE, which is the whole reason the test is
  // a Poisson tail: 2 against an expected 2.07 is agreement, but so is 0, and
  // so is 5 — the registered rate came from a count of TWO and cannot support
  // a tighter claim than that.
  it('does not cry drift on counts the registered rate can explain', () => {
    for (const n of [0, 1, 2, 3, 4, 5]) {
      const r = a.rateDrift('device_silent', n, 28, NOW);
      assert.equal(r.state, a.RATE_STATES.INDISTINGUISHABLE,
        `count ${n} over 28 days should not read as drift (expected 2.07)`);
    }
  });

  // ⛔ `indistinguishable`, NEVER `consistent`. Observing 0 against an expected
  // 2.07 is p=0.126 and settles nothing; reporting it as agreement would be a
  // failed measurement recorded as a fact.
  it('names the agreement state so it cannot be read as proof', () => {
    assert.equal(a.RATE_STATES.INDISTINGUISHABLE, 'indistinguishable');
    assert.ok(!Object.values(a.RATE_STATES).includes('consistent'));
  });

  it('is unmeasurable rather than wrong on a bad input', () => {
    assert.equal(a.rateDrift('no_such_detector', 5, 28, NOW).state, a.RATE_STATES.UNMEASURABLE);
    assert.equal(a.rateDrift('device_silent', 5, 0, NOW).state, a.RATE_STATES.UNMEASURABLE);
    assert.equal(a.rateDrift('device_silent', null, 28, NOW).state, a.RATE_STATES.UNMEASURABLE);
    assert.equal(a.rateDrift('device_silent', -1, 28, NOW).state, a.RATE_STATES.UNMEASURABLE);
  });

  // ⛔ THE BOUND IS EXPLICIT BECAUSE EXCEEDING IT FABRICATES AGREEMENT.
  // exp(-lambda) underflows to 0 above ~745, which makes the cumulative sum 0
  // and turns `atLeast` into a confident 1 — "not surprising" produced by an
  // arithmetic failure rather than by evidence.
  it('refuses a lambda it cannot compute instead of returning a confident 1', () => {
    assert.equal(a.poissonAtLeast(5, a.MAX_LAMBDA + 1), null);
    assert.equal(a.poissonAtMost(5, a.MAX_LAMBDA + 1), null);
    assert.ok(a.poissonAtLeast(5, 10) !== null);
  });

  it('poisson tails agree with known values', () => {
    // P(X=0 | 2.072) = e^-2.072
    assert.ok(Math.abs(a.poissonAtMost(0, 2.072) - Math.exp(-2.072)) < 1e-12);
    assert.equal(a.poissonAtLeast(0, 2.072), 1);
    assert.ok(Math.abs(a.poissonAtMost(50, 2.072) - 1) < 1e-9);
  });

  // ⛔ THE AGE IS A FACT BESIDE THE VERDICT, NEVER MIXED INTO IT. 90 days is a
  // review cadence and a judgement; the tail test is the evidence, and folding
  // a date into a statistical state would let one masquerade as the other.
  it('reports measurement age separately from the statistical verdict', () => {
    const r = a.rateDrift('device_silent', 17, 28, NOW);
    assert.equal(r.measuredOn, '2026-10-06');
    assert.equal(r.measurementAgeDays, 39);
    assert.equal(r.reviewOverdue, false);
    const later = a.rateDrift('device_silent', 17, 28, new Date('2027-06-01T00:00:00Z'));
    assert.equal(later.reviewOverdue, true);
    // the verdict itself must not have moved because the clock did
    assert.equal(later.state, r.state);
  });

  // ⛔ THIS CASE EXISTS BECAUSE THE FIRST DRAFT OF THE TEST ABOVE MISSED A
  // MUTATION. Seeding the state from `reviewOverdue` passed all 35 tests: the
  // age assertion used a DRIFTED count, and the drift branch overwrites the
  // seed, so the contamination was invisible on exactly the input chosen to
  // check for it. The property only has teeth on a count the registered rate
  // CAN explain — where nothing later overrides the seed.
  it('an overdue measurement does not become a statistical verdict', () => {
    const overdue = new Date('2027-06-01T00:00:00Z');
    const r = a.rateDrift('device_silent', 2, 28, overdue);
    assert.equal(r.reviewOverdue, true, 'precondition: the measurement must be overdue');
    assert.equal(r.state, a.RATE_STATES.INDISTINGUISHABLE,
      'an old measurement is a review fact, not evidence of drift — the tail test is the evidence');
    assert.equal(r.p, null);
  });

  // ⛔ REPORTS, NEVER REFUSES. A meta-check that could disarm a detector would
  // be the guard-that-cannot-fire pattern aimed at the alerting engine itself,
  // and this product's rule is that monitoring runs in every state.
  it('every registered detector still has evidence and nothing throws on drift', () => {
    for (const key of Object.keys(a.EVIDENCE)) {
      assert.doesNotThrow(() => a.assertRegisteredDetector(key));
      assert.doesNotThrow(() => a.rateDrift(key, 9999, 28, NOW));
      assert.equal(a.rateDrift(key, 9999, 28, NOW).state, a.RATE_STATES.DRIFTED_HIGH);
    }
  });
});

// ── ⛔ A RUN THAT SPANS THE WINDOW'S LEFT EDGE (roadmap row 29) ───────────
//
// `loadReportingGrid` generates hours from `now() - N days`, so index 0 of the
// grid ADVANCES EVERY HOUR. A silence run that really began earlier has its
// `startAt` clamped to that moving edge, and three things followed:
//
//   1. the dispatcher's natural_key changed every hour, so each tick cleared
//      the previous key as RESOLVED and raised the next as a fresh alert —
//      ~24 false resolve/renotify pairs a day;
//   2. `hours` SHRANK by one every hour, so a silence that is not ending
//      looked like one that was getting better;
//   3. `startAt` was reported as a start time nobody measured.
//
// ⛔ It is not a rare condition, it is a DEFERRED one: every run crosses the
// 28-day boundary eventually and churns for its own duration while it does.
const anomalyData = require('../lib/engines/anomalyDetectionsData');

// One grid, with an explicit reported/silent pattern. `shift` drops leading
// hours, which is exactly what the advancing window does to the same fleet.
function gridFrom(pattern, shift = 0) {
  return pattern.slice(shift).map((reported, i) => ({
    at: new Date(Date.UTC(2026, 9, 1, shift + i)),
    reported: reported === 1,
  }));
}

describe('⛔ a silence run truncated by the evidence window', () => {
  // silent for the first 6 hours of the window, then reporting — i.e. a run
  // that began before we were looking.
  const PATTERN = [0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1];

  it('is marked truncated, because its start is outside the evidence', () => {
    const { runs } = a.detectSilence(gridFrom(PATTERN));
    assert.equal(runs.length, 1);
    assert.equal(runs[0].truncated, true);
    assert.equal(runs[0].hours, 6);
  });

  it('a run wholly inside the window is NOT truncated', () => {
    const { runs } = a.detectSilence(gridFrom([1, 1, 0, 0, 0, 1, 1]));
    assert.equal(runs.length, 1);
    assert.equal(runs[0].truncated, false, 'this start WAS observed and must be keyed on');
  });

  it('⛔ THE KEY SURVIVES AN ADVANCING WINDOW — the churn itself', () => {
    // The same fleet, the same silence, judged an hour apart. Before the fix
    // these two keys differed, so the dispatcher resolved one and raised the
    // other every single hour.
    const keyAt = (shift) => {
      const { runs } = a.detectSilence(gridFrom(PATTERN, shift));
      assert.equal(runs.length, 1, `shift ${shift} should still see the run`);
      return {
        key: anomalyData.naturalKey('anomaly_device_silent', 'dev-1', runs[0].startAt, runs[0].truncated),
        startAt: runs[0].startAt.toISOString(),
        hours: runs[0].hours,
      };
    };
    const t0 = keyAt(0);
    const t1 = keyAt(1);
    const t2 = keyAt(2);

    // The inputs really do move — otherwise this test proves nothing.
    assert.notEqual(t0.startAt, t1.startAt, 'the window edge must advance for this to be a test');
    assert.ok(t1.hours < t0.hours, 'and the observed length really does shrink');

    // The key does not.
    assert.equal(t0.key, t1.key);
    assert.equal(t1.key, t2.key);
    assert.match(t0.key, /start-before-window$/);
    // ⛔ And it carries no timestamp at all — the defect was a key built from a
    // boundary that moves, so a key containing any instant is suspect.
    assert.doesNotMatch(t0.key, /\d{4}-\d{2}-\d{2}T/);
  });

  it('a run inside the window still keys on its real start, and two runs differ', () => {
    const { runs } = a.detectSilence(gridFrom([1, 0, 0, 1, 1, 0, 0, 0, 1]));
    assert.equal(runs.length, 2);
    const keys = runs.map((r) => anomalyData.naturalKey('anomaly_device_silent', 'dev-1', r.startAt, r.truncated));
    assert.notEqual(keys[0], keys[1], 'two separate events must be two alerts');
    for (const k of keys) assert.match(k, /\d{4}-\d{2}-\d{2}T/, 'an observed start IS the key');
  });

  it('⛔ the sentence says AT LEAST, because `hours` is a lower bound', () => {
    const { runs } = a.detectSilence(gridFrom(PATTERN));
    const truncated = a.describeSilence(runs[0], 'TFM-RN');
    assert.match(truncated, /AT LEAST 6 hours/);
    assert.match(truncated, /began before/i);
    // Said plainly it would under-state a silence that may have lasted weeks,
    // and it is the only number the operator gets.
    assert.doesNotMatch(truncated, /for 6 consecutive hours/);

    const whole = a.detectSilence(gridFrom([1, 1, 0, 0, 0, 1])).runs[0];
    assert.match(a.describeSilence(whole, 'TFM-RN'), /for 3 consecutive hours/);
    assert.doesNotMatch(a.describeSilence(whole, 'TFM-RN'), /AT LEAST/);
  });

  it('the denied-spike detector marks truncation too, in the same shape', () => {
    // ⛔ The identical defect lived in BOTH run builders. A fix applied to one
    // of two detectors is a defect waiting to be rediscovered.
    const src = fs.readFileSync(
      path.join(__dirname, '..', 'lib', 'engines', 'anomalyDetections.js'), 'utf8'
    );
    assert.match(src, /truncated: run\.startIndex === 0/, 'detectSpike must mark it');
    assert.match(src, /truncated: start === 0/, 'detectSilence must mark it');
  });

  it('a finding carries the flag, so no consumer can read `hours` as exact', () => {
    const src = fs.readFileSync(
      path.join(__dirname, '..', 'lib', 'engines', 'anomalyDetectionsData.js'), 'utf8'
    );
    // Both findings — silence and spike.
    assert.equal((src.match(/hoursAreLowerBound: !!run\.truncated/g) || []).length, 2);
    assert.equal((src.match(/run\.startAt, run\.truncated\)/g) || []).length, 2);
  });
});


// ---------------------------------------------------------------------------
// Roadmap row 59 — the detector went QUIET exactly as the silence became TOTAL
// ---------------------------------------------------------------------------
//
// ⛔ A device dark for 27 days raised an alert and one dark for 29 raised
// NOTHING, because an all-silent grid was read as "this device has never
// reported". The window cannot tell the two apart at ANY length — widening it
// only moves the boundary — so the answer comes from an unbounded MAX over the
// permanent rollups instead.

const ALL_SILENT = H(24 * 28, false);
const NOW = new Date(Date.UTC(2026, 9, 29, 12));

describe('⛔ a firewall silent for LONGER than the whole window', () => {
  it('⛔ THE DEFECT: the grid alone cannot tell it from a device that never existed', () => {
    // Both of these are the SAME 28 days of nothing. Only the fact from
    // outside the window separates them, which is why this read exists.
    const never = a.detectSilence(ALL_SILENT, { lastReportedAt: null });
    const stopped = a.detectSilence(ALL_SILENT, {
      lastReportedAt: new Date(Date.UTC(2026, 8, 1, 7)), now: NOW,
    });
    assert.equal(never.state, 'no_data');
    assert.equal(never.runs.length, 0);
    assert.equal(stopped.state, 'stopped_before_window');
    assert.equal(stopped.runs.length, 1, 'the most completely silent firewall must produce a finding');
  });

  it('⛔ OMITTING the fact is its own answer, never either verdict', () => {
    // The dangerous direction would be guessing. It degrades to today's
    // behaviour — no finding — but it must not ASSERT something false about
    // the device while doing so.
    const r = a.detectSilence(ALL_SILENT);
    assert.equal(r.state, 'no_data');
    assert.doesNotMatch(r.reason, /never reported/,
      'claiming "never reported" with nothing to support it IS the bug');
    assert.match(r.reason, /cannot be told apart|no last-reported/i);
  });

  it('a string, or an Invalid Date, is not a measurement', () => {
    for (const bad of ['2026-09-01', new Date('nope'), 0, {}]) {
      const r = a.detectSilence(ALL_SILENT, { lastReportedAt: bad });
      assert.equal(r.state, 'no_data', `${String(bad)} must not arm the detector`);
    }
  });

  it('⛔ `hours` STAYS NULL and the measured span travels under its own name', () => {
    const [run] = a.detectSilence(ALL_SILENT, {
      lastReportedAt: new Date(Date.UTC(2026, 8, 1, 7)), now: NOW,
    }).runs;
    // The window is 28 days of silence, so `hours` could trivially be set to
    // 672 — and that would be the window's length wearing a measurement's
    // clothes, exactly the fabricated-edge defect `truncated` was added for.
    assert.equal(run.hours, null);
    assert.equal(run.startAt, null, 'the start is outside the evidence');
    assert.equal(run.truncated, true);
    assert.equal(run.silentDays, 58, 'measured from the permanent rollups: 09-01 to 10-29');
    assert.ok(run.lastReportedAt instanceof Date);
  });

  it('with no clock the span is unknown, never zero', () => {
    const [run] = a.detectSilence(ALL_SILENT, {
      lastReportedAt: new Date(Date.UTC(2026, 8, 1, 7)),
    }).runs;
    assert.equal(run.silentDays, null);
    const sentence = a.describeSilence(run, 'TFM-RN');
    assert.doesNotMatch(sentence, /\b0 days\b/, 'a missing clock must never read as "silent 0 days"');
  });

  it('⛔ the sentence states a MEASURED span, not a lower bound', () => {
    const [run] = a.detectSilence(ALL_SILENT, {
      lastReportedAt: new Date(Date.UTC(2026, 8, 1, 7)), now: NOW,
    }).runs;
    const sentence = a.describeSilence(run, 'TFM-RN');
    assert.match(sentence, /no syslog for 58 days/);
    assert.match(sentence, /permanent rollups/);
    // ⛔ NOT the truncated wording: that one is honestly a lower bound because
    // its evidence is the grid. This one's evidence is a permanent table, and
    // calling it "AT LEAST" would under-state the worst case on the fleet.
    assert.doesNotMatch(sentence, /AT LEAST/);
    // and never the no-data claim
    assert.doesNotMatch(sentence, /never/i);
    // the standing consequence is still said
    assert.match(sentence, /reads as healthy everywhere else/);
  });

  it('⛔ THE KEY DOES NOT CHURN WHEN A TRUNCATED RUN BECOMES A TOTAL ONE', () => {
    // A silence crosses the window edge first (truncated), then falls entirely
    // outside it (stopped_before_window). Those are the same ongoing event, so
    // a different key would make the dispatcher resolve the alert and raise it
    // again on the day the firewall became MOST silent.
    const edge = a.detectSilence(
      [...H(6, false), ...H(18, true, 6)], { lastReportedAt: new Date(Date.UTC(2026, 8, 1, 7)) }
    ).runs[0];
    const total = a.detectSilence(ALL_SILENT, {
      lastReportedAt: new Date(Date.UTC(2026, 8, 1, 7)), now: NOW,
    }).runs[0];
    const key = (r) => anomalyData.naturalKey('anomaly_device_silent', 'dev-1', r.startAt, r.truncated);
    assert.equal(key(edge), key(total));
    assert.match(key(total), /start-before-window$/);
    assert.doesNotMatch(key(total), /\d{4}-\d{2}-\d{2}T/);
    assert.doesNotMatch(key(total), /null/, 'a null start must not become part of the key');
  });
});

describe('⛔ row 59 — the WIRING, which is the part that goes untested', () => {
  // The whole defect was one `continue`. Pinning detectSilence alone would
  // have left it live.
  const DEV = '11111111-1111-4111-8111-111111111111';
  function stubPool({ lastAt, gridReported = false }) {
    const seen = [];
    return {
      seen,
      query: async (sql) => {
        seen.push(sql);
        if (/max\(bucket_hour\) AS last_at/.test(sql)) {
          return { rows: lastAt ? [{ device_id: DEV, last_at: lastAt }] : [] };
        }
        if (/generate_series/.test(sql)) {
          return {
            rows: Array.from({ length: 24 * 28 }, (_, i) => ({
              device_id: DEV, device_name: 'TFM-RN',
              at: new Date(Date.UTC(2026, 9, 1, i)), reported: gridReported,
            })),
          };
        }
        return { rows: [] };
      },
    };
  }

  it('⛔ gatherAnomalies REPORTS a firewall dark for longer than the window', async () => {
    const pool = stubPool({ lastAt: new Date(Date.UTC(2026, 7, 20, 5)) });
    const { findings, states } = await anomalyData.gatherAnomalies(pool, { now: NOW });
    const silent = findings.filter((f) => f.detector === 'device_silent');
    assert.equal(silent.length, 1, 'this is the finding that did not exist');
    assert.equal(silent[0].stoppedBeforeWindow, true);
    assert.equal(silent[0].hours, null);
    assert.equal(silent[0].silentDays, 70);
    assert.ok(silent[0].lastReportedAt instanceof Date);
    assert.match(silent[0].naturalKey, /start-before-window$/);
    assert.equal(states.device_silent.stopped_before_window, 1);
    assert.equal(states.device_silent.no_data, 0, 'it is JUDGED, not a coverage gap');
  });

  it('a device the rollups have never seen still yields nothing', async () => {
    const pool = stubPool({ lastAt: null });
    const { findings, states } = await anomalyData.gatherAnomalies(pool, { now: NOW });
    assert.equal(findings.filter((f) => f.detector === 'device_silent').length, 0);
    assert.equal(states.device_silent.no_data, 1);
    assert.equal(states.device_silent.stopped_before_window, 0);
  });

  it('⛔ the unbounded read happens even when the grid is empty', async () => {
    // Otherwise the wiring is true only on the happy path, and a future
    // short-circuit would restore the blind spot with every test still green.
    const pool = {
      queries: [],
      query: async (sql) => { pool.queries.push(sql); return { rows: [] }; },
    };
    await anomalyData.gatherAnomalies(pool, { now: NOW });
    assert.ok(
      pool.queries.some((q) => /max\(bucket_hour\) AS last_at/.test(q)),
      'loadLastReported must be called unconditionally'
    );
  });

  it('⛔ it reads the PERMANENT rollups and is never bounded by the window', async () => {
    const pool = { query: async () => ({ rows: [] }) };
    let sql = '';
    await anomalyData.loadLastReported({ query: async (q) => { sql = q; return { rows: [] }; } });
    assert.match(sql, /FROM syslog_rollup_hourly/);
    assert.doesNotMatch(sql, /syslog_events/, 'an event scan is refused product-wide');
    assert.doesNotMatch(sql, /days'\)::interval|now\(\) -/,
      'a window bound here would reintroduce the boundary this read exists to escape');
    assert.ok(pool);
  });

  it('⛔ the coverage line counts it as JUDGED, not as a gap', () => {
    const src = fs.readFileSync(
      path.join(__dirname, '..', 'components', 'alerts', 'AnomalyPanel.js'), 'utf8'
    );
    // A firewall this detector DID judge must not be reported as one it could
    // not reach — that sentence is the panel's denominator.
    assert.match(src, /const measured = \(Number\(s\.measured\) \|\| 0\) \+ \(Number\(s\.stopped_before_window\) \|\| 0\)/);
  });
});
