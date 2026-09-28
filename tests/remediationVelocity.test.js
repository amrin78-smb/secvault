'use strict';

// tests/remediationVelocity.test.js
//
// Pins lib/engines/remediationVelocity.js — A8, how long a known vulnerability
// stays open on this fleet.
//
// ⛔ WHAT THESE TESTS ARE FOR. Survival analysis has one failure mode that
// matters here and it is this codebase's own: an observation that has not
// finished, counted as one that finished quickly. On the live fleet EVERY
// observation is censored — 0 of 16 firewalls have changed version in 74 days —
// so a estimator that quietly drops censored rows would report a remediation
// time computed from an empty set, and one that treats "still open" as "closed
// at the cutoff" would report the fleet's total failure to patch as a median of
// ~60 days. Both are confident, plausible and wrong.
//
// The second class: S(t) = 1.0 means EVERYTHING IS STILL VULNERABLE. It reads
// as "100%", which any renderer would tint green.

const { describe, it, test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { stripComments } = require('./stripComments');

const {
  buildExposure,
  kaplanMeier,
  summariseVelocity,
  velocityHeadline,
  daysBetween,
  OUTCOMES,
  VELOCITY_CLAIM,
  MEDIAN_NOT_REACHED,
} = require('../lib/engines/remediationVelocity');

const NOW = new Date('2026-09-28T00:00:00Z');
const d = (s) => new Date(s);

/** The live shape: advisory known months after the vendor published it. */
function row(over) {
  return Object.assign({
    device_id: 'dev-1',
    device_name: 'TSR-TL',
    cve_id: 'CVE-2026-24858',
    kev_listed: true,
    priority_band: 'patch_now',
    cvss_score: '9.4',
    advisory_published_at: d('2026-01-28T00:00:00Z'),
    advisory_known_at: d('2026-07-16T00:00:00Z'),
    device_first_seen_at: d('2026-07-16T00:00:00Z'),
    remediated_at: null,
  }, over || {});
}

// ── the exposure clock ─────────────────────────────────────────────────────

describe('⛔ the exposure start is the LATER of two dates, and neither alone', () => {
  it('a device first seen AFTER the advisory starts its clock at the device', () => {
    // Charging a firewall for weeks before SecVault had ever collected from it
    // is measuring our own install date and calling it the operator's delay.
    const e = buildExposure(row({
      advisory_known_at: d('2026-07-16T00:00:00Z'),
      device_first_seen_at: d('2026-09-09T00:00:00Z'),
    }), NOW);
    assert.equal(Math.round(e.daysSinceKnown), 19, 'from the device, not from the advisory');
  });

  it('an advisory ingested AFTER the device starts its clock at the advisory', () => {
    // The reverse error: charging a firewall for an advisory that did not exist.
    const e = buildExposure(row({
      advisory_known_at: d('2026-09-01T00:00:00Z'),
      device_first_seen_at: d('2026-07-16T00:00:00Z'),
    }), NOW);
    assert.equal(Math.round(e.daysSinceKnown), 27, 'from the advisory, not from the device');
  });

  it('⛔ neither date available is UNKNOWN_START, not day zero', () => {
    // The "we could not measure this" case. An exposure with no usable start is
    // real and must be COUNTED — it simply has no time axis to sit on. Dating
    // it to the cutoff would report it as brand new, which is the friendliest
    // possible lie about an exposure that may be years old.
    const e = buildExposure(row({ advisory_known_at: null, device_first_seen_at: null }), NOW);
    assert.equal(e.outcome, OUTCOMES.UNKNOWN_START);
    assert.equal(e.daysSinceKnown, null, 'never 0');
    assert.equal(e.exposureStart, null);
  });

  it('only one of the two dates still yields a clock', () => {
    for (const over of [
      { advisory_known_at: null },
      { device_first_seen_at: null },
    ]) {
      const e = buildExposure(row(over), NOW);
      assert.notEqual(e.outcome, OUTCOMES.UNKNOWN_START);
      assert.ok(e.daysSinceKnown > 0);
    }
  });

  it('⛔ a negative age is null, never 0 and never an absolute value', () => {
    // Two clocks disagreeing is not a measurement. Same call vpn_sessions makes.
    const e = buildExposure(row({ advisory_known_at: d('2027-01-01T00:00:00Z') }), NOW);
    assert.equal(e.daysSinceKnown, null);
    assert.equal(daysBetween(d('2026-09-28'), d('2026-09-01')), null);
  });

  it('a junk date is null, not a coerced epoch', () => {
    for (const bad of ['', 'nope', {}, [], NaN, 0, false]) {
      const e = buildExposure(row({ advisory_known_at: bad, device_first_seen_at: bad }), NOW);
      assert.equal(e.outcome, OUTCOMES.UNKNOWN_START, `${JSON.stringify(bad)} must not parse`);
    }
  });
});

describe('⛔ BOTH clocks are reported and neither substitutes for the other', () => {
  it('the live KEV shape carries two very different ages', () => {
    const e = buildExposure(row(), NOW);
    // 2026-07-16 -> 2026-09-28
    assert.equal(Math.round(e.daysSinceKnown), 74);
    // 2026-01-28 -> 2026-09-28 : the firewall was actually exposed this long
    assert.equal(Math.round(e.daysSincePublished), 243);
    assert.ok(e.daysSincePublished > e.daysSinceKnown * 3,
      'the two clocks differ by months and a single blended figure would hide it');
  });

  it('⛔ a missing publish date does NOT fall back to the known date', () => {
    // Substituting one clock for the other reports one measurement under the
    // other one's name — the failed-read-as-a-fact rule, wearing a date.
    const e = buildExposure(row({ advisory_published_at: null }), NOW);
    assert.equal(e.daysSincePublished, null);
    assert.ok(e.daysSinceKnown > 0, 'the other clock still works');
    assert.equal(e.unawareDays, null, 'the gap is unknowable without both');
  });

  it('the window SecVault could not have reported is its own field', () => {
    const e = buildExposure(row(), NOW);
    assert.equal(Math.round(e.unawareDays), 169,
      'published 2026-01-28, first ingested 2026-07-16');
  });

  it('every exposure declares itself a lower bound', () => {
    // Left-censored on both sides: the device may have run the affected version
    // before we collected, and the advisory was real before we ingested it.
    assert.equal(buildExposure(row(), NOW).isLowerBound, true);
  });
});

// ── the estimator ──────────────────────────────────────────────────────────

describe('⛔ Kaplan-Meier with every subject censored', () => {
  const allOpen = Array.from({ length: 10 }, (_, i) =>
    buildExposure(row({ device_id: `d${i}`, remediated_at: null }), NOW));

  it('reports 0 events and 10 censored, losing none of them', () => {
    const km = kaplanMeier(allOpen);
    assert.equal(km.events, 0);
    assert.equal(km.censored, 10);
    assert.equal(km.atRisk, 10, 'censored subjects are still subjects');
  });

  it('⛔ the median is NOT REACHED — null, not the largest observation', () => {
    const km = kaplanMeier(allOpen);
    assert.equal(km.medianDays, MEDIAN_NOT_REACHED);
    assert.equal(km.medianDays, null);
    // The tempting wrong answer: 74, the longest anyone has been waiting.
    assert.notEqual(km.medianDays, 74);
  });

  it('the curve has no drop points at all, because nothing happened', () => {
    assert.deepEqual(kaplanMeier(allOpen).points, []);
  });

  it('⛔ summarise reports allCensored and a 0% remediation rate', () => {
    const s = summariseVelocity(allOpen, NOW);
    assert.equal(s.remediated, 0);
    assert.equal(s.open, 10);
    assert.equal(s.remediatedPct, 0);
    assert.equal(s.allCensored, true, 'this is the flag a renderer must key on');
    assert.equal(s.medianDaysToRemediate, null);
  });

  it('⛔ AND THE HEADLINE IS NEVER "ok"', () => {
    // S(t) = 1.0 is "100% still vulnerable". The single most dangerous render
    // available here is a green 100%.
    const h = velocityHeadline(summariseVelocity(allOpen, NOW));
    assert.equal(h.tone, 'bad');
    assert.notEqual(h.tone, 'ok');
    assert.match(h.text, /Not one of 10 open exposures was remediated/);
    assert.match(h.text, /median time-to-patch does not exist/);
  });

  it('the headline names the KEV exposures separately', () => {
    const h = velocityHeadline(summariseVelocity(allOpen, NOW));
    assert.match(h.text, /known-exploited/);
    assert.match(h.text, /74 days/);
  });
});

describe('the estimator on data that does contain events', () => {
  // Built so the curve genuinely crosses 50%: 3 remediated early, 1 late, 1 open.
  const mixed = [
    buildExposure(row({ device_id: 'a', remediated_at: d('2026-07-26T00:00:00Z') }), NOW), // 10d
    buildExposure(row({ device_id: 'b', remediated_at: d('2026-07-26T00:00:00Z') }), NOW), // 10d
    buildExposure(row({ device_id: 'c', remediated_at: d('2026-08-05T00:00:00Z') }), NOW), // 20d
    buildExposure(row({ device_id: 'e', remediated_at: d('2026-09-14T00:00:00Z') }), NOW), // 60d
    buildExposure(row({ device_id: 'f', remediated_at: null }), NOW),                      // open
  ];

  it('drops at each event time and not at censorings', () => {
    const km = kaplanMeier(mixed);
    assert.equal(km.events, 4);
    assert.equal(km.censored, 1);
    assert.deepEqual(km.points.map((p) => p.days), [10, 20, 60]);
  });

  it('the survival function decreases monotonically', () => {
    const pts = kaplanMeier(mixed).points;
    for (let i = 1; i < pts.length; i++) {
      assert.ok(pts[i].survivingPct <= pts[i - 1].survivingPct);
    }
  });

  it('the median is the first time survival reaches or crosses 50%', () => {
    const km = kaplanMeier(mixed);
    // 2 events of 5 at t=10 -> 60%; 1 of 3 at t=20 -> 40% (crosses)
    assert.equal(km.medianDays, 20);
  });

  it('⛔ a censored subject is still at risk at its own time', () => {
    // The convention that makes censoring correct: it removes a subject from
    // the denominator AFTER that instant, not before.
    const km = kaplanMeier(mixed);
    assert.equal(km.points[0].atRisk, 5);
  });

  it('a real median produces an "ok" headline', () => {
    const h = velocityHeadline(summariseVelocity(mixed, NOW));
    assert.equal(h.tone, 'ok');
    assert.match(h.text, /within 20 days/);
  });
});

describe('⛔ an exposure with no start is counted, never silently dropped', () => {
  const withUnknown = [
    buildExposure(row({ device_id: 'a', remediated_at: d('2026-07-26T00:00:00Z') }), NOW),
    buildExposure(row({ device_id: 'b', advisory_known_at: null, device_first_seen_at: null }), NOW),
    buildExposure(row({ device_id: 'c' }), NOW),
  ];

  it('it is excluded from the CURVE but present in the totals', () => {
    const s = summariseVelocity(withUnknown, NOW);
    assert.equal(s.exposures, 3, 'the denominator keeps it');
    assert.equal(s.unknownStart, 1);
    assert.equal(s.curve.atRisk, 2, 'the curve cannot place it on a time axis');
  });

  it('dropping it would have inflated the remediation rate', () => {
    const s = summariseVelocity(withUnknown, NOW);
    // 1 of 3, not 1 of 2.
    assert.ok(Math.abs(s.remediatedPct - 33.33) < 0.1);
  });
});

describe('the engine takes its clock and does not read one', () => {
  it('the same rows at a later cutoff age', () => {
    const later = new Date('2026-12-28T00:00:00Z');
    const a = buildExposure(row(), NOW).daysSinceKnown;
    const b = buildExposure(row(), later).daysSinceKnown;
    assert.ok(b > a + 80, 'the cutoff is an input, so a fixed fixture can be tested');
  });

  it('tolerates junk input everywhere rather than throwing', () => {
    for (const bad of [null, undefined, 'nope', 42, {}]) {
      assert.equal(typeof buildExposure(bad, NOW), 'object');
      assert.ok(Array.isArray(kaplanMeier(bad).points));
      assert.equal(typeof summariseVelocity(bad, NOW), 'object');
      assert.equal(typeof velocityHeadline(bad).tone, 'string');
    }
  });

  it('an empty fleet says nothing can be said, rather than reporting success', () => {
    const h = velocityHeadline(summariseVelocity([], NOW));
    assert.equal(h.tone, 'unknown');
    assert.notEqual(h.tone, 'ok');
  });
});

// ── the source rule ────────────────────────────────────────────────────────

describe('⛔ `assessed_at` may never be used as an exposure clock', () => {
  const SRC = path.join(__dirname, '..', 'lib', 'engines', 'remediationVelocity.js');

  test('the engine does not reference it outside comments', () => {
    // ⛔ THE WHOLE REASON THIS ENGINE NEEDED A DIFFERENT CLOCK. All 246 live
    // `device_cve_assessments` rows carry the SAME `assessed_at` — today's —
    // because the row is rewritten on every match run. A duration measured from
    // it reports every exposure as hours old and resets every six hours.
    // Comments STRIPPED FIRST: this file discusses the field at length.
    const src = stripComments(fs.readFileSync(SRC, 'utf8'));
    assert.ok(!/assessed_at/.test(src),
      'assessed_at records when SecVault last looked, not when the exposure began');
  });

  test('the claim is exported so a UI cannot quietly strengthen it', () => {
    assert.match(VELOCITY_CLAIM, /lower bounds/);
    assert.match(VELOCITY_CLAIM, /still open/);
    // ⛔ It must not promise we watched anyone patch anything.
    assert.ok(!/\bfixed\b/i.test(VELOCITY_CLAIM) || /never/i.test(VELOCITY_CLAIM));
  });

  test('⛔ no outcome name claims more than a version string change', () => {
    // We observed a version move, not a remediation programme.
    assert.deepEqual(Object.values(OUTCOMES).sort(),
      ['open', 'remediated', 'unknown_start']);
  });
});
