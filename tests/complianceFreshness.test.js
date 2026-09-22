'use strict';
// tests/complianceFreshness.test.js
//
// ⛔ THE CASE THAT MATTERS IS "WE STOPPED MEASURING", NOT "THE SCORE IS BAD".
// A compliance audit runs inside collectAndStore gated on
// `result.configCollected`, so a firewall that stops being collectable stops
// being audited and its findings freeze at whatever they last were. Measured on
// the live fleet 2026-09-22: TSR_EKC's score was 28 days old and TSR-TL's 10,
// rendered beside fourteen ~12-hour-old ones with nothing distinguishing them.
//
// Every assertion here is about a state that must NOT collapse into "fresh".

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  STATES, freshnessOf, complianceFreshness, ageLabel, freshnessNote, summariseFreshness,
  pullIntervalHours, AGEING_AFTER_INTERVALS, STALE_AFTER_INTERVALS,
} = require('../lib/engines/complianceFreshness');

const NOW = new Date('2026-09-22T12:00:00Z');
const H = 3600000;
const hoursAgo = (h) => new Date(NOW.getTime() - h * H);
const env = (v) => (v === undefined ? {} : { CONFIG_PULL_INTERVAL_HOURS: String(v) });

describe('⛔ the states that must never read as fresh', () => {
  it('never audited is its OWN state, not "very stale"', () => {
    // A device added yesterday has no result to be old. Calling it stale puts
    // an alarming age on a device nothing is wrong with; calling it fresh is
    // worse.
    for (const v of [null, undefined, '']) {
      assert.equal(freshnessOf(v, NOW, env()).state, STATES.NEVER);
    }
    assert.equal(ageLabel(freshnessOf(null, NOW, env())), 'never run');
  });

  it('⛔ an unparseable timestamp is UNKNOWN, never fresh', () => {
    for (const v of ['not a date', 'yesterday', {}]) {
      assert.equal(freshnessOf(v, NOW, env()).state, STATES.UNKNOWN,
        `${JSON.stringify(v)} must not be treated as a recent audit`);
    }
  });

  it('⛔ a FUTURE timestamp is a clock disagreement, not freshness', () => {
    const ahead = new Date(NOW.getTime() + 6 * H);
    assert.equal(freshnessOf(ahead, NOW, env()).state, STATES.UNKNOWN);
  });

  it('and hours/intervals are null in every unmeasurable state, never 0', () => {
    for (const v of [null, 'nonsense', new Date(NOW.getTime() + H)]) {
      const f = freshnessOf(v, NOW, env());
      assert.equal(f.hours, null, 'a zero age would read as "just now"');
      assert.equal(f.intervals, null);
    }
  });
});

describe('⛔ staleness is measured in cadences, not absolute hours', () => {
  it('a fleet on a 6h pull and one on a weekly pull do not share a definition of late', () => {
    // 48h is fresh on a weekly cadence and badly stale on a 6-hourly one.
    assert.equal(freshnessOf(hoursAgo(48), NOW, env(168)).state, STATES.FRESH);
    assert.equal(freshnessOf(hoursAgo(48), NOW, env(6)).state, STATES.STALE);
  });

  it('the boundaries are the documented multiples of the cadence', () => {
    const iv = 24;
    const at = (mult) => freshnessOf(hoursAgo(iv * mult), NOW, env(iv)).state;
    assert.equal(at(1), STATES.FRESH);
    assert.equal(at(AGEING_AFTER_INTERVALS), STATES.FRESH, 'exactly at the bound is not yet late');
    assert.equal(at(AGEING_AFTER_INTERVALS + 0.5), STATES.AGEING);
    assert.equal(at(STALE_AFTER_INTERVALS), STATES.AGEING);
    assert.equal(at(STALE_AFTER_INTERVALS + 0.5), STATES.STALE);
  });

  it('the cadence is read from the environment at call time, not captured', () => {
    assert.equal(pullIntervalHours(env(6)), 6);
    assert.equal(pullIntervalHours(env()), 24, 'the documented default');
    assert.equal(pullIntervalHours(env('nonsense')), 24, 'junk falls back, never to 0');
    assert.equal(pullIntervalHours(env(0)), 24, 'a zero cadence would divide by zero');
    assert.equal(pullIntervalHours(env(-5)), 24);
  });

  it('reproduces the live fleet exactly', () => {
    // The two devices that were genuinely behind, and one that was not.
    assert.equal(freshnessOf(hoursAgo(669), NOW, env(24)).state, STATES.STALE, 'TSR_EKC');
    assert.equal(freshnessOf(hoursAgo(252), NOW, env(24)).state, STATES.STALE, 'TSR-TL');
    assert.equal(freshnessOf(hoursAgo(12), NOW, env(24)).state, STATES.FRESH, 'the other fourteen');
  });
});

describe('⛔ the wording keeps the score worth something', () => {
  it('a stale result is described as real evidence about an OLD config', () => {
    // Wording it as garbage pushes people to ignore the page rather than fix
    // the collection, which is the opposite of the intent.
    const note = freshnessNote(freshnessOf(hoursAgo(669), NOW, env(24)), 'TSR_EKC');
    assert.match(note, /the score is real/);
    assert.match(note, /describes an old\s+configuration/);
    assert.match(note, /[Cc]ollection/, 'it names the likely cause');
    assert.match(note, /TSR_EKC/);
    // ⛔ And it says what re-running would NOT achieve, because the page that
    // shows this sentence also shows a Run Audit button.
    assert.match(note, /re-running the checks would only re-read the same old one/);
  });

  it('never-run is described as a collection gap, not a clean result', () => {
    const note = freshnessNote(freshnessOf(null, NOW, env()), 'NewFW');
    assert.match(note, /never been audited/);
    assert.match(note, /gap in collection, not a clean result/);
  });

  it('an age is never rendered as "0 hours ago"', () => {
    assert.equal(ageLabel(freshnessOf(hoursAgo(0.2), NOW, env())), 'under an hour ago');
    assert.match(ageLabel(freshnessOf(hoursAgo(12), NOW, env())), /^12h ago$/);
    assert.match(ageLabel(freshnessOf(hoursAgo(240), NOW, env())), /^10 days ago$/);
  });
});

describe('⛔ the fleet roll-up names who is behind', () => {
  const fleet = [
    { deviceName: 'TSR_EKC', lastRunAt: hoursAgo(669) },
    { deviceName: 'TSR-TL', lastRunAt: hoursAgo(252) },
    { deviceName: 'SMT', lastRunAt: hoursAgo(11) },
    { deviceName: 'NewFW', lastRunAt: null },
  ];

  it('counts every state and names the devices, not just the number', () => {
    // "2 firewalls are behind" sends someone hunting through sixteen rows.
    const s = summariseFreshness(fleet, NOW, env(24));
    assert.equal(s.total, 4);
    assert.equal(s.stale, 2);
    assert.equal(s.fresh, 1);
    assert.equal(s.never, 1);
    assert.deepEqual(s.behind, ['TSR_EKC', 'TSR-TL', 'NewFW']);
  });

  it('⛔ a never-run device counts as behind — it is not quietly excluded', () => {
    const s = summariseFreshness([{ deviceName: 'NewFW', lastRunAt: null }], NOW, env());
    assert.equal(s.behind.length, 1, 'no result at all is the most behind a device can be');
  });

  it('an all-fresh fleet reports nothing to chase', () => {
    const s = summariseFreshness([{ deviceName: 'A', lastRunAt: hoursAgo(3) }], NOW, env(24));
    assert.deepEqual(s.behind, []);
    assert.equal(s.fresh, 1);
  });

  it('accepts either key shape, since two callers spell it differently', () => {
    const s = summariseFreshness([{ name: 'A', last_run_at: hoursAgo(600) }], NOW, env(24));
    assert.equal(s.stale, 1);
  });
});

describe('⛔ the age belongs to the EVIDENCE, never to the evaluation', () => {
  // runComplianceAuditForDevice reads the newest device_configs row whatever
  // its age and stamps detected_at = now(). So the two timestamps genuinely
  // diverge, and grading on the later one reports a stale config as verified.
  const live = { evidenceAt: hoursAgo(1116), evaluatedAt: hoursAgo(669) }; // TSR_EKC

  it('⛔ grades on the config time, NOT the more flattering audit time', () => {
    const f = complianceFreshness(live, NOW, env(24));
    assert.equal(Math.round(f.hours), 1116,
      'grading on the 669h audit time would understate the evidence by 18 days');
    assert.equal(f.state, STATES.STALE);
  });

  it('a "run checks now" press today would NOT make it fresh', () => {
    // The button re-reads the same old config and stamps a new timestamp.
    const after = complianceFreshness(
      { evidenceAt: hoursAgo(1116), evaluatedAt: NOW }, NOW, env(24));
    assert.equal(after.state, STATES.STALE,
      'a fresh evaluation over stale evidence must not read as fresh');
    assert.equal(after.evaluatedAgainstOldConfig, true);
  });

  it('reports the lag, and flags an evaluation run against an already-old config', () => {
    const f = complianceFreshness(live, NOW, env(24));
    assert.equal(Math.round(f.evaluationLagHours), 447, '1116 - 669');
    assert.equal(f.evaluatedAgainstOldConfig, true);
  });

  it('⛔ the flag fires at the CADENCE, not at any lag above zero', () => {
    // The fixtures either side of this were lag 0 and lag 447, so a mutation
    // from `lag > expectedHours` to `lag > 0` survived — and that version
    // flags every device whose audit is even minutes newer than its config,
    // which is ALL of them on a healthy fleet. A flag that is always on says
    // nothing, and this one exists to mark the one shape that actually
    // misleads: checks re-run over evidence that was ALREADY late.
    const at = (evidenceH, evaluatedH, iv) => complianceFreshness(
      { evidenceAt: hoursAgo(evidenceH), evaluatedAt: hoursAgo(evaluatedH) }, NOW, env(iv)
    );
    // lag 20h on a 24h cadence — the config was still current when the checks ran.
    assert.equal(at(100, 80, 24).evaluatedAgainstOldConfig, false);
    // lag 30h on the same cadence — it was not.
    assert.equal(at(100, 70, 24).evaluatedAgainstOldConfig, true);
    // ⛔ THE BOUNDARY ITSELF: exactly one cadence is not yet late.
    assert.equal(at(100, 76, 24).evaluatedAgainstOldConfig, false);
    assert.equal(at(100, 75.9, 24).evaluatedAgainstOldConfig, true);
    // ⛔ AND IT MOVES WITH THE CADENCE. The identical 20h lag IS late on a
    // 6-hourly pull — which is what makes this a multiple and not a constant.
    assert.equal(at(100, 80, 6).evaluatedAgainstOldConfig, true);
  });

  it('⛔ a NEGATIVE lag is never a flag — the audit predating its evidence is not "old"', () => {
    // evaluatedAt older than evidenceAt is the ordinary healthy shape (the
    // config was collected after the last audit). It must not read as an
    // evaluation run against a stale config.
    const f = complianceFreshness(
      { evidenceAt: hoursAgo(2), evaluatedAt: hoursAgo(50) }, NOW, env(24)
    );
    assert.ok(f.evaluationLagHours < 0);
    assert.equal(f.evaluatedAgainstOldConfig, false);
  });

  it('a healthy device has a near-zero lag and is not flagged', () => {
    const f = complianceFreshness(
      { evidenceAt: hoursAgo(12), evaluatedAt: hoursAgo(12) }, NOW, env(24));
    assert.equal(f.state, STATES.FRESH);
    assert.equal(Math.round(f.evaluationLagHours), 0);
    assert.equal(f.evaluatedAgainstOldConfig, false);
  });

  it('⛔ an unmeasurable end leaves the lag NULL, never 0', () => {
    // 0 would read as "evaluated the moment it was collected" -- the most
    // reassuring possible wrong answer.
    for (const t of [
      { evidenceAt: null, evaluatedAt: hoursAgo(3) },
      { evidenceAt: hoursAgo(3), evaluatedAt: null },
      { evidenceAt: hoursAgo(3), evaluatedAt: 'nonsense' },
      {},
      null,
    ]) {
      const f = complianceFreshness(t, NOW, env(24));
      assert.equal(f.evaluationLagHours, null, JSON.stringify(t));
      assert.equal(f.evaluatedAgainstOldConfig, false,
        'an unknown lag is not a flag -- it is an unknown');
    }
  });

  it('carries the evaluation verdict alongside rather than discarding it', () => {
    const f = complianceFreshness(live, NOW, env(24));
    assert.equal(f.evaluation.state, STATES.STALE);
    assert.equal(Math.round(f.evaluation.hours), 669);
  });
});
