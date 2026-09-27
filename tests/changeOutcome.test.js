'use strict';

// tests/changeOutcome.test.js — A7, change → traffic outcome.
//
// ⛔ THE MEASUREMENT THAT SHAPED THIS ENGINE, so the tests defend it:
//
//   24h either side of a CONFIG CHANGE (61 changes)   avg delta  +13.6%
//   24h either side of an ORDINARY DAY (284 pairs)    avg delta  +17.6%
//
// The change-adjacent delta is SMALLER than ordinary variation, and per-change
// deltas (-92% to +126%) all sit inside the fleet's own p90 of 113.8%. A naive
// before/after percentage would have produced 61 plausible "effects" from pure
// noise. So the tests below care far more about what this engine REFUSES to
// conclude than about what it concludes.
//
// Per-device p90 of daily variation spans 23.2% (HRIS) to 284.3% (Vietnam-YCC),
// a 12x spread — which is why the band is per device and never fleet-wide.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
  buildBaseline, judgeChange, assessDevice, summariseOutcomes, median, quantile,
  OUTCOME_CLAIM, VERDICTS, BAND_QUANTILE, MIN_BASELINE_PAIRS,
} = require('../lib/engines/changeOutcome');

// A steady series: ~5% wobble, 20 days. Enough pairs, real spread.
function steady(days = 20, base = 1000) {
  const out = [];
  for (let i = 0; i < days; i += 1) {
    const wobble = [0, 40, -30, 55, -20, 35, -45, 25, -15, 50][i % 10];
    out.push({ day: `2026-09-${String(i + 1).padStart(2, '0')}`, events: base + wobble });
  }
  return out;
}

describe('median', () => {
  it('handles odd and even lengths, and an empty list', () => {
    assert.equal(median([1, 2, 3]), 2);
    assert.equal(median([1, 2, 3, 4]), 2.5);
    assert.equal(median([]), null);
  });
});

describe('⛔ the baseline is the control, and it can refuse to exist', () => {
  it('builds from a series with enough day-pairs', () => {
    const b = buildBaseline(steady());
    assert.equal(b.usable, true);
    assert.ok(b.observations >= MIN_BASELINE_PAIRS);
    assert.ok(b.medianAbsPct > 0);
    assert.ok(b.mad > 0);
    assert.ok(b.bandPct > b.medianAbsPct, 'the band must sit above the median');
    assert.equal(b.quantile, BAND_QUANTILE);
    assert.ok(b.resolutionPct > 0, 'and it states the finest rate this n can express');
  });

  it('⛔ too few day-pairs is insufficient_baseline, not a band of zero', () => {
    const b = buildBaseline(steady(4));
    assert.equal(b.usable, false);
    assert.equal(b.reason, VERDICTS.INSUFFICIENT_BASELINE);
    assert.equal(b.bandPct, null, 'null, never 0 — a band of 0 flags everything');
    assert.equal(b.needed, MIN_BASELINE_PAIRS, 'and it states what it needed');
  });

  it('⛔ a band of ZERO is degenerate and refuses to judge anything', () => {
    // A device whose daily traffic never moves has no spread to compare
    // against. A band of 0 would flag every movement, however small.
    const flat = [];
    for (let i = 0; i < 20; i += 1) {
      flat.push({ day: `2026-09-${String(i + 1).padStart(2, '0')}`, events: 1000 });
    }
    const b = buildBaseline(flat);
    assert.equal(b.usable, false);
    assert.equal(b.reason, VERDICTS.BASELINE_DEGENERATE);
    assert.equal(b.bandPct, null);
  });

  it('a flat-but-alternating series is still usable — MAD 0 no longer breaks it', () => {
    // ⛔ This case USED to be fatal, because median+MAD divided by MAD. The
    // quantile rule has no such singularity, and the series does have spread.
    const alt = [];
    for (let i = 0; i < 20; i += 1) {
      alt.push({ day: `2026-09-${String(i + 1).padStart(2, '0')}`, events: i % 2 ? 1100 : 1000 });
    }
    const b = buildBaseline(alt);
    assert.equal(b.mad, 0, 'MAD really is 0 here');
    assert.equal(b.usable, true, 'and that is no longer a reason to refuse');
    assert.ok(b.bandPct > 0);
  });

  it('⛔ a zero previous day is DROPPED from the baseline, not treated as infinite', () => {
    // A device that was silent and then spoke is a coverage event, not a
    // variability observation. Including it would inflate the band enormously
    // and hide every real movement behind it.
    const withGap = steady(20);
    withGap[5].events = 0;
    const b = buildBaseline(withGap);
    assert.equal(b.usable, true);
    assert.ok(Number.isFinite(b.bandPct));
    assert.ok(b.observations < 19, 'the pair after the zero day cannot be used');
  });

  it('tolerates junk without throwing, and reports it as unusable', () => {
    for (const bad of [undefined, null, 'x', 42, {}, [], [{}], [{ day: null, events: null }]]) {
      const b = buildBaseline(bad);
      assert.equal(b.usable, false);
      assert.equal(typeof b.observations, 'number');
    }
  });

  it('numeric strings from pg are measurements; falsy coercions are not', () => {
    const asStrings = steady().map((r) => ({ day: r.day, events: String(r.events) }));
    assert.equal(buildBaseline(asStrings).usable, true);
    const withNulls = steady().map((r, i) => ({ day: r.day, events: i === 3 ? null : r.events }));
    assert.equal(buildBaseline(withNulls).observations < 19, true, 'a null day yields no pair');
  });
});

describe('⛔ a movement is judged against the DEVICE’S OWN band', () => {
  const baseline = buildBaseline(steady());

  it('a movement inside the band is INDISTINGUISHABLE, not "no effect"', () => {
    const r = judgeChange({ beforeEvents: 1000, afterEvents: 1050 }, baseline);
    assert.equal(r.verdict, VERDICTS.INDISTINGUISHABLE);
    assert.equal(r.deltaPct, 5);
    assert.equal(r.ordinaryDays, 19, 'and it says how many ordinary days it was compared with');
    assert.ok(r.largerThanDays !== null);
  });

  it('a movement far outside the band EXCEEDS it', () => {
    const r = judgeChange({ beforeEvents: 1000, afterEvents: 9000 }, baseline);
    assert.equal(r.verdict, VERDICTS.EXCEEDED);
    assert.equal(r.deltaPct, 800);
    assert.equal(r.largerThanDays, r.ordinaryDays,
      'larger than every ordinary day observed — a claim the reader can check');
  });

  it('⛔ the SAME delta gets opposite verdicts on two different devices', () => {
    // This is the measured 12x spread made a test. A fleet-wide band would be
    // wrong at both ends: it would flag routine variation on the noisy device
    // and miss a real movement on the quiet one.
    const quiet = [];
    const noisy = [];
    for (let i = 0; i < 20; i += 1) {
      const day = `2026-09-${String(i + 1).padStart(2, '0')}`;
      quiet.push({ day, events: 1000 + [0, 3, -2, 5, -1, 4, -3, 2, -4, 1][i % 10] });
      noisy.push({ day, events: 1000 + [0, 900, -500, 1200, -400, 800, -700, 600, -300, 1100][i % 10] });
    }
    const q = judgeChange({ beforeEvents: 1000, afterEvents: 1400 }, buildBaseline(quiet));
    const n = judgeChange({ beforeEvents: 1000, afterEvents: 1400 }, buildBaseline(noisy));
    assert.equal(q.verdict, VERDICTS.EXCEEDED, '+40% is enormous for a steady firewall');
    assert.equal(n.verdict, VERDICTS.INDISTINGUISHABLE, 'and routine for a volatile one');
  });

  it('a DROP is judged on magnitude, not direction', () => {
    const r = judgeChange({ beforeEvents: 1000, afterEvents: 20 }, baseline);
    assert.equal(r.verdict, VERDICTS.EXCEEDED);
    assert.ok(r.deltaPct < 0, 'and the sign is preserved for the reader');
  });
});

describe('⛔ the states that must never read as "no effect"', () => {
  const baseline = buildBaseline(steady());

  it('no traffic either side is NO_TRAFFIC_WINDOW', () => {
    // Live, 133 of 203 config changes predate the traffic rollup entirely.
    // Reporting those as unaffected would be a claim about 66% of the change
    // history built from its own absence.
    for (const w of [
      { beforeEvents: null, afterEvents: 500 },
      { beforeEvents: 500, afterEvents: null },
      { beforeEvents: 0, afterEvents: 500 },
      {},
      null,
    ]) {
      const r = judgeChange(w, baseline);
      assert.equal(r.verdict, VERDICTS.NO_TRAFFIC_WINDOW, JSON.stringify(w));
      assert.equal(r.deltaPct, null);
      assert.equal(r.largerThanDays, null);
    }
  });

  it('⛔ an unusable baseline withholds the JUDGEMENT but still reports the delta', () => {
    // The delta is a real measurement; what is missing is something to judge it
    // against. Hiding the number would be its own dishonesty.
    const r = judgeChange({ beforeEvents: 1000, afterEvents: 2000 }, buildBaseline(steady(4)));
    assert.equal(r.verdict, VERDICTS.INSUFFICIENT_BASELINE);
    assert.equal(r.deltaPct, 100, 'the measurement survives');
    assert.equal(r.largerThanDays, null, 'the judgement does not');
  });

  it('a degenerate baseline reports ITS OWN reason, not insufficient_baseline', () => {
    const flat = [];
    for (let i = 0; i < 20; i += 1) {
      flat.push({ day: `2026-09-${String(i + 1).padStart(2, '0')}`, events: 1000 });
    }
    const r = judgeChange({ beforeEvents: 1000, afterEvents: 5000 }, buildBaseline(flat));
    assert.equal(r.verdict, VERDICTS.BASELINE_DEGENERATE);
    assert.notEqual(r.verdict, VERDICTS.EXCEEDED, 'no spread means no finding, ever');
  });

  it('⛔ every verdict is a distinct value — none aliases another', () => {
    const vals = Object.values(VERDICTS);
    assert.equal(new Set(vals).size, vals.length);
    assert.ok(vals.includes(VERDICTS.INDISTINGUISHABLE));
    assert.ok(!vals.includes('no_effect'), 'there is no such verdict and there must not be');
  });
});

describe('per-device and fleet assembly', () => {
  it('assesses a device and counts every verdict', () => {
    const r = assessDevice(
      { deviceId: 'd1', deviceName: 'IDC FW', vendor: 'paloalto' },
      steady(),
      [
        { id: 'c1', detectedAt: '2026-09-10', beforeEvents: 1000, afterEvents: 1020 },
        { id: 'c2', detectedAt: '2026-09-12', beforeEvents: 1000, afterEvents: 9000 },
        { id: 'c3', detectedAt: '2026-09-14', beforeEvents: 0, afterEvents: 900 },
      ]
    );
    assert.equal(r.changeCount, 3);
    assert.equal(r.byVerdict[VERDICTS.INDISTINGUISHABLE], 1);
    assert.equal(r.byVerdict[VERDICTS.EXCEEDED], 1);
    assert.equal(r.byVerdict[VERDICTS.NO_TRAFFIC_WINDOW], 1);
    assert.equal(r.exceeded.length, 1);
    assert.equal(r.exceeded[0].changeId, 'c2');
  });

  it('a device with no changes is not an error and not a finding', () => {
    const r = assessDevice({ deviceId: 'd1' }, steady(), []);
    assert.equal(r.changeCount, 0);
    assert.equal(r.exceeded.length, 0);
    assert.equal(r.baseline.usable, true);
  });

  it('⛔ the summary counts devices WITHOUT a baseline separately', () => {
    // A device we could not build a band for is not a device whose changes were
    // harmless, and the two must not share a number.
    const s = summariseOutcomes([
      assessDevice({ deviceId: 'a' }, steady(),
        [{ id: '1', detectedAt: '2026-09-10', beforeEvents: 1000, afterEvents: 1010 }]),
      assessDevice({ deviceId: 'b' }, steady(4),
        [{ id: '2', detectedAt: '2026-09-02', beforeEvents: 1000, afterEvents: 5000 }]),
    ]);
    assert.equal(s.devices, 2);
    assert.equal(s.devicesWithUsableBaseline, 1);
    assert.equal(s.devicesWithoutBaseline, 1);
    assert.equal(s.changes, 2);
    assert.equal(s.byVerdict[VERDICTS.INSUFFICIENT_BASELINE], 1);
    assert.equal(s.claim, OUTCOME_CLAIM);
  });

  it('⛔ the summary carries no score, grade, band-percentage or pass rate', () => {
    const s = summariseOutcomes([assessDevice({ deviceId: 'a' }, steady(), [])]);
    for (const k of Object.keys(s)) {
      assert.ok(!/score|grade|pct|percent|rate|health/i.test(k), `summary must not carry "${k}"`);
    }
  });

  it('tolerates junk without throwing', () => {
    for (const bad of [undefined, null, 'x', 42, {}]) {
      assert.equal(summariseOutcomes(bad).devices, 0);
      const r = assessDevice(bad, bad, bad);
      assert.equal(r.changeCount, 0);
    }
  });
});

describe('⛔ CO-OCCURRENCE, NEVER CAUSATION', () => {
  const SRC = path.join(__dirname, '..', 'lib', 'engines', 'changeOutcome.js');

  // ⛔ Comments stripped FIRST, and the stripper is PROVEN below rather than
  // assumed — this repo has repeatedly had a source scan satisfied by the very
  // comment explaining the thing it was hunting.
  function code() {
    return fs.readFileSync(SRC, 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/(^|[^:])\/\/.*$/gm, '$1');
  }

  it('the stripper works (proven, not assumed)', () => {
    const raw = fs.readFileSync(SRC, 'utf8');
    // The header deliberately contains "causation" in prose.
    assert.match(raw, /causation/i, 'the header should discuss causation');
    assert.ok(!/causation/i.test(code()), 'and the stripped source must not contain it');
  });

  it('⛔ no causal vocabulary in any string this engine emits', () => {
    const strings = [OUTCOME_CLAIM, ...Object.values(VERDICTS)];
    const banned = /\b(caused?|causing|because|due to|resulted in|impact(ed|s)?|broke|led to)\b/i;
    for (const s of strings) {
      assert.ok(!banned.test(s), `causal wording in: ${s}`);
    }
    assert.ok(!banned.test(code()), 'nor anywhere in the emitting source');
  });

  it('the claim states what is compared AND what is not observed', () => {
    assert.match(OUTCOME_CLAIM, /normally varies|day to day/i, 'names the control');
    assert.match(OUTCOME_CLAIM, /cannot say|does not observe/i, 'and the refusal');
  });

  it('the exceeded verdict is not named like a fault', () => {
    assert.match(VERDICTS.EXCEEDED, /variation/, 'it names the band, not a verdict about the change');
    assert.ok(!/fail|bad|break|caused/i.test(VERDICTS.EXCEEDED));
  });

  it('⛔ the decision rule is the empirical quantile, not median+MAD', () => {
    // Median + MAD with Iglewicz-Hoaglin's 3.5 cut-off was tried and MEASURED
    // WRONG on this fleet: it flagged 17.3% of ORDINARY days as exceeding
    // normal variation. Nothing may quietly restore it as the rule.
    assert.equal(BAND_QUANTILE, 0.95);
    const c = code();
    assert.ok(!/MODIFIED_Z|0\.6745/.test(c),
      'the z-score cut-off must not come back as the decision rule');
    assert.ok(!/\bstdev|standardDeviation|variance\b/i.test(c),
      'nor mean + sigma — firewall traffic is heavy-tailed');
    // The rule is a comparison against bandPct and nothing else.
    assert.match(c, /abs\s*>\s*baseline\.bandPct/);
  });

  it('quantile interpolates and degrades safely', () => {
    assert.equal(quantile([], 0.95), null);
    assert.equal(quantile([7], 0.95), 7);
    assert.equal(quantile([0, 10], 0.5), 5);
    assert.equal(quantile([0, 100], 0.95), 95);
  });

  it('⛔ median and MAD are DESCRIPTION — neither may decide a verdict', () => {
    // They are still reported because they are useful to a reader. The test
    // that matters is that the verdict does not consult them.
    const b = buildBaseline(steady());
    assert.ok(b.medianAbsPct > 0 && b.mad >= 0, 'both still reported');
    const withoutDescriptive = { ...b, medianAbsPct: 9999, mad: 9999 };
    const a = judgeChange({ beforeEvents: 1000, afterEvents: 1050 }, b);
    const z = judgeChange({ beforeEvents: 1000, afterEvents: 1050 }, withoutDescriptive);
    assert.equal(a.verdict, z.verdict, 'corrupting median/MAD must not change the verdict');
  });
});

describe('⛔ A7 — a window reaching outside the collection period is refused', () => {
  // The first live run produced FOUR changes dated 2026-09-08 — the rollup's own
  // first day — with deltas of +814%, +691% and +239% that cleared every band.
  // Their 24h "before" window lay in the hours the collector had only just
  // started, so `before_events` was small for reasons that have nothing to do
  // with the firewall. Confident, plausible, and completely wrong.
  const series = steady();           // 2026-09-01 .. 2026-09-20

  it('a change at the very START of the observed period is WINDOW_INCOMPLETE', () => {
    const r = assessDevice({ deviceId: 'd' }, series,
      [{ id: 'c', detectedAt: '2026-09-01T06:00:00Z', beforeEvents: 40, afterEvents: 1000 }]);
    assert.equal(r.changes[0].verdict, VERDICTS.WINDOW_INCOMPLETE);
    assert.equal(r.changes[0].deltaPct, null, 'and the delta is withheld, not printed');
    assert.equal(r.changes[0].windowComplete, false);
  });

  it('a change at the very END is refused for the same reason', () => {
    const r = assessDevice({ deviceId: 'd' }, series,
      [{ id: 'c', detectedAt: '2026-09-20T18:00:00Z', beforeEvents: 1000, afterEvents: 40 }]);
    assert.equal(r.changes[0].verdict, VERDICTS.WINDOW_INCOMPLETE);
  });

  it('a change comfortably inside the period IS judged', () => {
    const r = assessDevice({ deviceId: 'd' }, series,
      [{ id: 'c', detectedAt: '2026-09-10T12:00:00Z', beforeEvents: 1000, afterEvents: 1010 }]);
    assert.equal(r.changes[0].windowComplete, true);
    assert.equal(r.changes[0].verdict, VERDICTS.INDISTINGUISHABLE);
  });

  it('⛔ an UNKNOWN or unparseable timestamp is incomplete, never assumed fine', () => {
    for (const at of [undefined, null, '', 'not-a-date']) {
      const r = assessDevice({ deviceId: 'd' }, series,
        [{ id: 'c', detectedAt: at, beforeEvents: 1000, afterEvents: 9000 }]);
      assert.equal(r.changes[0].verdict, VERDICTS.WINDOW_INCOMPLETE, String(at));
    }
  });

  it('⛔ completeness is tested BEFORE the traffic — an incomplete window with plenty '
    + 'of events is still refused', () => {
    // It is the COMPARISON that is invalid, not the data, so a healthy-looking
    // pair of numbers must not rescue it.
    const r = assessDevice({ deviceId: 'd' }, series,
      [{ id: 'c', detectedAt: '2026-09-01T00:00:00Z', beforeEvents: 5000, afterEvents: 5200 }]);
    assert.equal(r.changes[0].verdict, VERDICTS.WINDOW_INCOMPLETE);
  });

  it('the observed period is reported so a reader can see the bound', () => {
    const r = assessDevice({ deviceId: 'd' }, series, []);
    assert.ok(r.observedFrom instanceof Date);
    assert.ok(r.observedTo instanceof Date);
    assert.ok(r.observedTo > r.observedFrom);
    assert.equal(r.windowHours, 24);
  });

  it('a wider window refuses MORE changes, and that is the honest trade', () => {
    // Live: 61 changes have 24h either side, only 18 have 7 days. A wider
    // window buys precision by discarding most of the subject.
    const change = [{ id: 'c', detectedAt: '2026-09-03T00:00:00Z', beforeEvents: 1000, afterEvents: 1010 }];
    const narrow = assessDevice({ deviceId: 'd' }, series, change, { windowHours: 24 });
    const wide = assessDevice({ deviceId: 'd' }, series, change, { windowHours: 24 * 7 });
    assert.equal(narrow.changes[0].windowComplete, true);
    assert.equal(wide.changes[0].windowComplete, false);
  });
});
